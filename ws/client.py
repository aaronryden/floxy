import asyncio
import websockets
import ssl

ssl_context = ssl.create_default_context()
ssl_context.check_hostname = False
ssl_context.verify_mode = ssl.CERT_NONE


async def test_websocket():
    uri = "wss://yourexample.com:8443/test"
    async with websockets.connect(uri, ssl=ssl_context) as websocket:
        await websocket.send("Hello, world!")
        response = await websocket.recv()
        print(f"Received: {response}")

asyncio.run(test_websocket())

