import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


import types  # noqa: E402

import pytest  # noqa: E402


@pytest.fixture
def plain_http(monkeypatch):
    """For tests that fake requests.get: the collector's guarded, size-limited requests go straight to it."""
    from domaincheck import collector, netguard

    class Shim:
        def get(self, url, stream=False, **kwargs):
            return collector.requests.get(url, **kwargs)

    stub = types.SimpleNamespace(session=lambda allow_private=False: Shim(), read_limited=lambda r, *a, **k: r,
                                 check_public=lambda *a, **k: None, MAX_ANSWER=netguard.MAX_ANSWER,
                                 PrivateAddress=netguard.PrivateAddress)
    monkeypatch.setattr(collector, "netguard", stub)
