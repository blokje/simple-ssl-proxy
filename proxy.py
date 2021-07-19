#!/usr/bin/env python3
import argparse
import datetime
import ssl
import tempfile
from typing import Awaitable, Callable, List
import logging

from aiohttp import web
import aiohttp
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        "Simple HTTPS proxy", formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument(
        "dest", help="Destination server to proxy to. Example: http://localhost:8000"
    )
    parser.add_argument("--host", "-H", type=str, default="127.0.0.1", help="address to listen to")
    parser.add_argument("--port", "-p", type=int, default=8443, help="port to listen to")
    parser.add_argument(
        "--names",
        type=str,
        default=["localhost"],
        nargs="+",
        help="ssl certificate names",
    )

    parser.add_argument("--cert", help="Use this as certificate")
    parser.add_argument("--key", help="Use this as key")
    return parser.parse_args()


def generate_certificate(host: str, names: List[str]):

    key = ec.generate_private_key(ec.SECP256R1())
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=10))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(host)] + [x509.DNSName(_) for _ in names]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )

    # aiohttp reuqires an SSLContext due to the use of asyncio eventloop. An SSL context can only
    # handle files, as such we are forced to store the certificate in a file.
    with tempfile.NamedTemporaryFile("wb") as certfile, tempfile.NamedTemporaryFile("wb") as keyfile:
        keyfile.write(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            )
        )
        certfile.write(cert.public_bytes(serialization.Encoding.PEM))

        keyfile.flush()
        certfile.flush()
        return load_ssl_context(certfile.name, keyfile.name)


def load_ssl_context(cert: str, key: str):
    print(f"Loading {cert} and {key}")
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
    ssl_context.load_cert_chain(cert, key)
    return ssl_context


def proxy(base_url: str) -> Callable[[web.Request], Awaitable[web.StreamResponse]]:



    async def inner_proxy(request: web.Request) -> web.StreamResponse:
        dest = f"{base_url}{request.path_qs}"
        async with aiohttp.ClientSession(headers=request.headers) as session:
            session.headers.pop("Host")
            data = await request.read()
            request = session.request(
                method=request.method,
                url=dest,
                data=data,
            )

            async with request as resp:
                response = web.Response(
                    body=await resp.read(),
                    headers=resp.headers,
                )

        return response
    return inner_proxy


def main():
    args = parse_args()

    if not args.cert and not args.key:
        ssl_context = generate_certificate(args.host, args.names)

    app = web.Application()
    app.router.add_route("*", r"/{path:.*}", proxy(args.dest))
    logging.basicConfig(level=logging.DEBUG)

    print("Open server to accept SSL certificate")
    web.run_app(app, ssl_context=ssl_context)


if __name__ == "__main__":
    main()
