from __future__ import annotations

import os
import ssl

import uvicorn


def run() -> None:
    insecure = os.getenv("FETCHER_DEV_INSECURE", "false").lower() == "true"
    options: dict[str, object] = {
        "app": "phishguard_fetcher.api:app",
        "host": "0.0.0.0",
        "port": int(os.getenv("FETCHER_PORT", "8443")),
        "workers": 1,
        "proxy_headers": False,
        "server_header": False,
    }
    if not insecure:
        options.update(
            ssl_keyfile=os.environ["FETCHER_TLS_KEY"],
            ssl_certfile=os.environ["FETCHER_TLS_CERT"],
            ssl_ca_certs=os.environ["FETCHER_CLIENT_CA"],
            ssl_cert_reqs=ssl.CERT_REQUIRED,
        )
    uvicorn.run(**options)


if __name__ == "__main__":
    run()

