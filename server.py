import asyncio
from aiohttp import web
import ssl
import os
import json
import time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import threading

CERTBOT_PORT = 8888  # sudo certbot certonly --standalone --http-01-port 8888 -d example.com
# Configuration file path
CONFIG_FILE = "config/domains.json"
DOMAIN_MAP = {}

class ConfigFileHandler(FileSystemEventHandler):
    """Watchdog event handler to reload the domain map on file change."""
    def on_modified(self, event):
        if event.src_path.endswith(CONFIG_FILE):
            print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Configuration file changed: {event.src_path}")
            load_domain_map()

def start_file_watcher():
    try:
        """Start watching the configuration file for changes."""
        config_path = os.path.dirname(CONFIG_FILE)
        event_handler = ConfigFileHandler()
        observer = Observer()
        observer.schedule(event_handler, path=config_path, recursive=False)
        observer.start()
        print(f"Started watching {config_path} for changes.")
    except Exception as e:
        print(f"Error starting file watcher {config_path}: {str(e)}")

def create_certbot_cert(domain):
    """Create a certificate using certbot."""
    try:
        print(f"Creating certificate for {domain} using certbot...")
        os.system(f"certbot certonly --standalone --http-01-port {CERTBOT_PORT} -d {domain}")
        print(f"Certificate created for {domain}.")
    except Exception as e:
        print(f"Error creating certificate for {domain}: {str(e)}")

def curl_domain_test(domain):
    """Test the domain using curl with a random value test header."""
    try:
        # Generate a random value for the test header
        test_header = "X-Test-Header"
        test_value = os.urandom(16).hex()
        # Use curl to test the domain with the test header
        os.system(f"curl -I -H '{test_header}: {test_value}' http://{domain}")
        if response == 0:
            print(f"Domain {domain} is reachable.")
            # check if the test header is present in the map
            if 'testHeader' in DOMAIN_MAP[domain]:
                # compare test header value
                if DOMAIN_MAP[domain]['testHeader'] == test_value:
                    print(f"Test header matches for {domain}.")
                    # safe to create certbot cert
                    create_certbot_cert(domain)
            else:
                print(f"Test header not found in domain map for {domain}. Request must not be routing correctly.")
        else:
            print(f"Domain {domain} is not reachable.")

    except Exception as e:
        print(f"Error testing domain {domain}: {str(e)}")

def test_domain(domain):
    # Test if the domain resolves to us
    try:
        # see if cert exists 
        cert_path = f"/etc/letsencrypt/live/{domain}/fullchain.pem"
        key_path = f"/etc/letsencrypt/live/{domain}/privkey.pem"
        if not (os.path.exists(cert_path) and os.path.exists(key_path)):
            print(f"Certificate for {domain} found.")
            response = os.system(f"ping -c 1 {domain}")
            if response == 0:
                # compare IP address to any address of this machine
                ip_address = os.popen(f"getent hosts {domain}").read().split()[0]
                local_ip = os.popen("hostname -I").read().strip()
                if ip_address in local_ip:
                    print(f"Domain {domain} resolves to this server.")
                    create_certbot_cert(domain)
                else:
                    print(f"Domain {domain} does not resolve to this server directly, fallback to HTTP layer.")
                    # curl this domain with test header
                    curl_domain_test(domain)
    except Exception as e:
        print(f"Error testing domain {domain}: {str(e)}")

def load_domain_map():
    global DOMAIN_MAP
    try:
        with open(CONFIG_FILE, "r") as file:
            DOMAIN_MAP = json.load(file)
            print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Loaded domain configuration: {DOMAIN_MAP}")
            for domain, config in DOMAIN_MAP.items():
                if 'upstream' not in config:
                    raise ValueError(f"Missing 'upstream' key for domain: {domain}")
                if 'redirectInsecure' not in config:
                    DOMAIN_MAP[domain]['redirectInsecure'] = False

                # Test each domain in the map on separate thread
                threading.Thread(target=test_domain, args=(domain,), daemon=True).start()
    except Exception as e:
        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Error loading domain configuration: {str(e)}")

# Initial loading of domain map
load_domain_map()

def generate_self_signed_cert(domain):
    """Generate a self-signed certificate if it does not exist."""
    cert_dir = f"selfsigned/{domain}"
    cert_path = f"{cert_dir}/fullchain.pem"
    key_path = f"{cert_dir}/privkey.pem"

    if not os.path.exists(cert_dir):
        os.makedirs(cert_dir)

    # Check if the certificate already exists
    if not os.path.exists(cert_path) or not os.path.exists(key_path):
        print(f"Generating self-signed certificate for {domain}...")
        cmd = (
            f"openssl req -x509 -newkey rsa:2048 -nodes -keyout {key_path} -out {cert_path} "
            f"-days 365 -subj '/CN={domain}'"
        )
        os.system(cmd)
        print(f"Self-signed certificate generated for {domain}.")

    # todo: check if cert expired

    return cert_path, key_path

async def handle_acme_challenge(request):
    """Handle ACME challenges from Let's Encrypt."""
    challenge_url = f"http://127.0.0.1:{CERTBOT_PORT}{request.path_qs}"
    print(f"Forwarding ACME challenge to: {challenge_url}")
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(challenge_url) as challenge_response:
                response = web.Response(status=challenge_response.status)
                response.headers.update(challenge_response.headers)
                response.body = await challenge_response.read()
                return response
    except Exception as e:
        print(f"Error forwarding ACME challenge: {str(e)}")
        return web.Response(text=f"ACME challenge forwarding failed: {str(e)}", status=502)

WEB_DOMAIN_SCHEMES = {}

async def handle_domain_proxy(request):
    """Proxy the incoming request to the appropriate upstream domain."""
    # Extract the host from the request
    host = request.headers.get("Host", "").split(":")[0]
    
    # Map the public domain to the upstream domain
    upstream_domain = DOMAIN_MAP[host]['upstream']
    if not upstream_domain in WEB_DOMAIN_SCHEMES:
        WEB_DOMAIN_SCHEMES[upstream_domain] = ['https', 'http']
    schemes = WEB_DOMAIN_SCHEMES[upstream_domain]

    # check for test header
    test_header = request.headers.get("X-Test-Header")
    if test_header:
        print(f"Test header found: {test_header}")
        # store header value
        if 'testHeader' not in DOMAIN_MAP[host]:
            DOMAIN_MAP[host]['testHeader'] = test_header



    for scheme in schemes:
        upstream_url = f"{scheme}://{upstream_domain}{request.path_qs}"
        print(f"Trying to proxy request to: {upstream_url}")

        try:
            async with aiohttp.ClientSession() as session:
                async with session.request(
                    method=request.method,
                    url=upstream_url,
                    headers=request.headers,
                    data=request.content,
                    ssl=False
                ) as upstream_response:

                    # Prepare the response headers
                    response = web.StreamResponse(status=upstream_response.status, headers=upstream_response.headers)
                    await response.prepare(request)

                    # Stream response body to client
                    async for chunk in upstream_response.content.iter_chunked(1024):
                        await response.write(chunk)

                    await response.write_eof()
                    print(f"Successfully proxied to: {upstream_url}")
                    if scheme == 'http':
                        WEB_DOMAIN_SCHEMES[upstream_domain] = ['http']
                    return response

        except Exception as e:
            print(f"Failed to proxy using {scheme}. Error: {str(e)}")
            continue  # Try the next scheme if the current one fails

    print(f"All schemes failed for {upstream_domain}. Returning 502.")
    return web.Response(text="502 Bad Gateway: Unable to reach upstream server", status=502)

WS_DOMAIN_SCHEMES = {}

async def handle_websocket_proxy(request):
    """Proxy WebSocket connections to the upstream server."""
    host = request.headers.get("Host", "").split(":")[0]
    upstream_domain = DOMAIN_MAP.get(host)
    upstream_domain = upstream_domain['upstream']

    if not upstream_domain in WS_DOMAIN_SCHEMES:
        WS_DOMAIN_SCHEMES[upstream_domain] = ['wss', 'ws']

    # Try both secure (wss) and non-secure (ws) schemes
    schemes = WS_DOMAIN_SCHEMES[upstream_domain]

    for scheme in schemes:
        upstream_url = f"{scheme}://{upstream_domain}{request.path_qs}"
        print(f"Attempting WebSocket proxy to: {upstream_url}")

        try:
            # Establish a WebSocket connection with the client
            ws_client = web.WebSocketResponse()
            await ws_client.prepare(request)

            # Establish a WebSocket connection with the upstream server
            async with aiohttp.ClientSession() as session:
                async with session.ws_connect(upstream_url, ssl=(scheme == 'wss')) as ws_server:
                    async def client_to_server():
                        async for msg in ws_client:
                            if msg.type == web.WSMsgType.TEXT:
                                await ws_server.send_str(msg.data)
                            elif msg.type == web.WSMsgType.BINARY:
                                await ws_server.send_bytes(msg.data)
                            elif msg.type == web.WSMsgType.CLOSE:
                                await ws_server.close()
                                break

                    async def server_to_client():
                        async for msg in ws_server:
                            if msg.type == aiohttp.WSMsgType.TEXT:
                                await ws_client.send_str(msg.data)
                            elif msg.type == aiohttp.WSMsgType.BINARY:
                                await ws_client.send_bytes(msg.data)
                            elif msg.type == aiohttp.WSMsgType.CLOSE:
                                await ws_client.close()
                                break

                    # Run both client-to-server and server-to-client concurrently
                    await asyncio.gather(client_to_server(), server_to_client())
                    if scheme == 'ws':
                        WS_DOMAIN_SCHEMES[upstream_domain] = ['ws']

            print(f"WebSocket successfully proxied via {scheme}.")
            return ws_client

        except Exception as e:
            print(f"Failed to proxy using {scheme}. Error: {str(e)}")
            continue  # Try the next scheme if the current one fails

    print(f"All schemes (wss, ws) failed for {upstream_domain}. Returning 502.")
    return web.Response(text="502 Bad Gateway: Unable to reach WebSocket upstream server", status=502)

# HTTP Listener (port 80) - Redirect to HTTPS
async def handle_redirect(request):
    host = request.headers.get("Host", "").split(":")[0]
    redirect_url = f"https://{host}{request.rel_url}"
    print(f"Redirecting HTTP to HTTPS: {redirect_url}")
    raise web.HTTPPermanentRedirect(redirect_url)

async def handle_request(request):
    """Main request handler."""
    host = request.headers.get("Host", "").split(":")[0]
    if host not in DOMAIN_MAP:
        print(f"Host {host} not found in DOMAIN_MAP.")
        return web.Response(text="403 Forbidden: Domain not allowed", status=403)

    domainConfig = DOMAIN_MAP[host]
    if request.scheme == "http" and domainConfig.get('redirectInsecure', False):
        return await handle_redirect(request)
    
    # Check if the request is for an ACME challenge
    if request.path.startswith('/.well-known/acme-challenge/'):
        return await handle_acme_challenge(request)
    
    # Detect WebSocket upgrade
    if "upgrade" in request.headers.get("Connection", "").lower() and request.headers.get("Upgrade", "").lower() == "websocket":
        return await handle_websocket_proxy(request)

    # Otherwise, handle as web proxy
    return await handle_domain_proxy(request)

ssl_context_cache = {}

async def start_server():
    tasks = []

    # Create a single SSL context for all domains using SNI
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_context.options |= ssl.OP_NO_COMPRESSION
    # ssl_context.session_cache_mode = ssl.SESS_CACHE_SERVER
    # ssl_context.set_session_id(b"proxy_server")

    def sni_callback(ssl_obj, server_name, context):
        """Dynamically switch SSL context based on SNI (Server Name Indication)."""
        print(f"SNI callback invoked for: {server_name}")

        # Use the requested server name to load the appropriate certificate
        if not server_name in DOMAIN_MAP:
            raise Exception(f"Server name '{server_name}' not found in DOMAIN_MAP")
        else:
            if server_name in ssl_context_cache:
                temp_context = ssl_context_cache[server_name]

            cert_path = f"/etc/letsencrypt/live/{server_name}/fullchain.pem"
            key_path = f"/etc/letsencrypt/live/{server_name}/privkey.pem"

            # Fallback to self-signed if Let's Encrypt certificates are not found
            if not (os.path.exists(cert_path) and os.path.exists(key_path)):
                print(f"Certificate for {server_name} not found. Falling back to self-signed.")
                cert_path, key_path = generate_self_signed_cert(server_name)
                # asyncio.create_task(run_in_thread(obtain_letsencrypt_cert, server_name))

            try:
                temp_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                temp_context.load_cert_chain(certfile=cert_path, keyfile=key_path)
                ssl_context_cache[server_name] = temp_context

                ssl_obj.context = temp_context
                print(f"Loaded certificate for {server_name}")
            except Exception as e:
                print(f"Error loading certificate for {server_name}: {e}")

    # Set the SNI callback to dynamically load certificates
    ssl_context.sni_callback = sni_callback

    # HTTPS Listener (port 443) - Single server with SNI support
    print("Starting HTTPS proxy on port 443 with SNI support...")
    runner_https = web.AppRunner(app)
    await runner_https.setup()
    site_https = web.TCPSite(runner_https, "0.0.0.0", 443, ssl_context=ssl_context)
    tasks.append(site_https.start())

    app_http = web.Application()
    app_http.router.add_route('*', '/{tail:.*}', handle_request)
    runner_http = web.AppRunner(app_http)
    await runner_http.setup()
    site_http = web.TCPSite(runner_http, "0.0.0.0", 80)
    tasks.append(site_http.start())

    if tasks:
        await asyncio.gather(*tasks)

async def main():
    print("Starting auto-reload config task...")
    threading.Thread(target=start_file_watcher, daemon=True).start()
    print("Starting the server...")
    await start_server()

    # Use an asyncio event to keep the loop alive
    stop_event = asyncio.Event()

    # Wait indefinitely until the event is set (which it never is)
    await stop_event.wait()

# Set up the application and routes
app = web.Application()
app.router.add_route('*', '/{tail:.*}', handle_request)

# Run the main event loop
asyncio.run(main())

