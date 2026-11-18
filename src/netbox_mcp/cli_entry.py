"""Console-script entry point.

``netbox-mcp oauth ...`` is dispatched without importing ``netbox_mcp.server``,
which parses and validates the whole server configuration at import time: the
admin commands must run with only the variables they need. Everything else
starts the server as before (``netbox_mcp.server:main`` stays usable).
"""

import sys


def main() -> None:
    if sys.argv[1:2] == ["oauth"]:
        from dotenv import load_dotenv

        from netbox_mcp.oauth.cli import oauth_cli

        load_dotenv()
        raise SystemExit(oauth_cli(sys.argv[2:]))

    from netbox_mcp.server import main as server_main

    server_main()


if __name__ == "__main__":
    main()
