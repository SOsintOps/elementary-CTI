"""Client-IP resolution behind the Caddy proxy (auth plan step 10).

X-Forwarded-For must be honoured only when the request peer is inside the
trusted proxy CIDR, and even then only its rightmost entry — everything to
the left travelled inside the client's own header and is spoofable.
"""

import pytest

from pestilentia.web.app import _resolve_client_ip

TRUSTED = "172.28.0.0/16"


@pytest.mark.parametrize(
    ("peer", "forwarded_for", "trusted_cidr", "expected"),
    [
        # No peer at all → nothing to record.
        (None, "203.0.113.9", TRUSTED, None),
        # No trusted CIDR configured (dev/test default) → peer wins, header ignored.
        ("203.0.113.9", "10.0.0.1", "", "203.0.113.9"),
        # Peer outside the CIDR sending a forged header → header ignored.
        ("203.0.113.9", "192.168.1.50", TRUSTED, "203.0.113.9"),
        # Peer is the proxy, single entry → the real client.
        ("172.28.0.3", "192.168.1.50", TRUSTED, "192.168.1.50"),
        # Client forged a left-hand entry; the proxy appended the real one.
        ("172.28.0.3", "1.2.3.4, 192.168.1.50", TRUSTED, "192.168.1.50"),
        # Proxy peer but no header (direct probe on the docker network) → peer.
        ("172.28.0.3", None, TRUSTED, "172.28.0.3"),
        # Garbage in the rightmost entry → fall back to the peer.
        ("172.28.0.3", "not-an-ip", TRUSTED, "172.28.0.3"),
        ("172.28.0.3", "192.168.1.50, ", TRUSTED, "172.28.0.3"),
        # Misconfigured CIDR must never raise on the request path.
        ("172.28.0.3", "192.168.1.50", "not-a-cidr", "172.28.0.3"),
        # IPv6 peer inside an IPv6 trusted network.
        ("fd00::3", "192.168.1.50", "fd00::/8", "192.168.1.50"),
        # IPv6 peer is simply not inside an IPv4 CIDR → peer.
        ("fd00::3", "192.168.1.50", TRUSTED, "fd00::3"),
    ],
)
def test_resolve_client_ip(peer, forwarded_for, trusted_cidr, expected):
    assert _resolve_client_ip(peer, forwarded_for, trusted_cidr) == expected
