"""Check registry. To add a check: create a module with NAME and `async def run(ctx)` returning
a list of Findings (or None if the check does not apply), then list it here."""

from . import cookies, cves, disclosure, email_dns, exposure, headers, tls, transport

ALL_CHECKS = [transport, tls, headers, cookies, disclosure, cves, exposure, email_dns]
CHECKS_BY_KEY = {m.__name__.rsplit(".", 1)[-1]: m for m in ALL_CHECKS}
