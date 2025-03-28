# FLOXY - a flexible web proxy
* inspired by Cloudflare's functionality

## Features
* **Real-Time Streaming Proxy:** Supports both HTTP and WebSocket traffic with seamless streaming.
* **Dynamic Configuration:** Automatically reloads changes from the `domains.json` file without downtime.
* **Secure SSL Handling:** Utilizes Let's Encrypt certificates for secure HTTPS connections.
* **Automatic Fallback to Self-Signed Certificates:** Ensures immediate availability even if SSL certificates are missing.
* **Smart Upstream Connection:** Prioritizes secure (HTTPS/WSS) connections and gracefully falls back to insecure (HTTP/WS) if needed.
* Append to your hosts file to test with the sample domain: `127.0.0.1 yourexample.com`