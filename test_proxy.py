import pytest
import asyncio
import time
import multiprocessing
from aiohttp import ClientSession, web
from server import main  # your reverse proxy server

# ---------- Dummy Upstream Web Server ----------
def run_dummy_server():
    async def handle(request):
        return web.Response(text="Hello from dummy server")

    async def start():
        app = web.Application()
        app.router.add_get('/api/test', handle)
        app.router.add_post('/api/test', handle)
        app.router.add_route('*', '/{tail:.*}', handle)
        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, '0.0.0.0', 3000)
        await site.start()
        await asyncio.Event().wait()  # run forever

    asyncio.run(start())

# ---------- Reverse Proxy Server ----------
def run_reverse_proxy():
    asyncio.run(main())

# ---------- Pytest Fixture ----------
@pytest.fixture(scope="session", autouse=True)
def launch_servers():
    reverse_proxy = multiprocessing.Process(target=run_reverse_proxy)
    dummy_backend = multiprocessing.Process(target=run_dummy_server)

    dummy_backend.start()
    time.sleep(1)  # Give dummy server a moment

    reverse_proxy.start()
    time.sleep(2)  # Give reverse proxy a moment

    yield

    reverse_proxy.terminate()
    dummy_backend.terminate()
    reverse_proxy.join()
    dummy_backend.join()

# ---------- Tests ----------
@pytest.mark.asyncio
async def test_reverse_proxy_basic_with_https_redirect():
    url = "http://example.com"
    headers = {"Host": "example.com"}

    async with ClientSession() as session:
        async with session.get(url + "/api/test", headers=headers, allow_redirects=False) as response:
            assert response.status == 308, f"Unexpected status: {response.status}"
            assert response.headers.get("Location") == "https://example.com/api/test", f"Unexpected redirect: {response.headers.get('Location')}"


import ssl
from aiohttp import TCPConnector

@pytest.mark.asyncio
async def test_reverse_proxy_test_header_with_https():
    url = "https://example.com"
    headers = {
        "Host": "example.com",
        "X-Test-Header": "pytest123"
    }

    connector = TCPConnector(ssl=False)  # ❗ Ignore SSL cert validation

    async with ClientSession(connector=connector) as session:
        async with session.get(url + "/api/test", headers=headers, allow_redirects=False) as response:
            assert response.status == 200


@pytest.mark.asyncio
async def test_reverse_proxy_test_header_no_redirect():
    url = "http://example2.com"
    headers = {
        "Host": "example2.com",
        "X-Test-Header": "pytest123"
    }

    async with ClientSession() as session:
        async with session.get(url + "/api/test", headers=headers, allow_redirects=False) as response:
            assert response.status == 200
