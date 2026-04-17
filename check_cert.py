import asyncio
import datetime
import os

from cryptography import x509
from cryptography.hazmat.backends import default_backend

LETSENCRYPT_CERT_DIR = "/etc/letsencrypt/live"


async def check_certificates_periodically(domain_map, interval_seconds=86400):
    while True:
        print(f"[{datetime.datetime.now()}] Checking domain certificates...")
        for domain in domain_map:
            cert_path = os.path.join(LETSENCRYPT_CERT_DIR, domain, "fullchain.pem")
            if os.path.exists(cert_path):
                try:
                    with open(cert_path, "rb") as cert_file:
                        cert_data = cert_file.read()
                        cert = x509.load_pem_x509_certificate(
                            cert_data, default_backend()
                        )
                        not_after = cert.not_valid_after
                        days_left = (not_after - datetime.datetime.utcnow()).days
                        print(
                            f"✅ {domain} cert valid until {not_after} ({days_left} days left)"
                        )

                        if days_left < 10:
                            print(
                                f"⚠️  Certificate for {domain} expires in {days_left} days! Consider renewing."
                            )
                except Exception as e:
                    print(f"❌ Failed to parse cert for {domain}: {e}")
            else:
                print(f"❌ No certificate found for {domain} at {cert_path}")

        await asyncio.sleep(interval_seconds)
