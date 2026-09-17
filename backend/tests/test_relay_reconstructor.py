import pytest
from backend.services.relay_reconstructor import RelayReconstructorService


def test_single_hop_parsing():
    received = [
        "from smtp.example.org (203.0.113.10) by mail.example.net with ESMTP id xyz for <user@example.com>; Sun, 7 Sep 2026 10:20:00 +0530"
    ]
    analysis = RelayReconstructorService.reconstruct_relay_path(received)
    assert len(analysis.header_order_hops) == 1
    assert len(analysis.transmission_order_hops) == 1

    hop = analysis.header_order_hops[0]
    assert hop.from_host == "smtp.example.org"
    assert hop.from_ip == "203.0.113.10"
    assert hop.by_host == "mail.example.net"
    assert hop.protocol == "ESMTP"
    assert hop.id == "xyz"
    assert hop.recipient == "user@example.com"
    assert "Sun, 7 Sep 2026" in hop.timestamp
    assert hop.raw == received[0]

    node = analysis.earliest_observable_node
    assert node.earliest_observable_ip == "203.0.113.10"
    assert node.confidence == "high"


def test_multiple_hops_ordering():
    # Top header (hop 1 in header order) = recipient MX (latest)
    # Bottom header (hop 2 in header order) = origin server (earliest)
    received = [
        "from relay.example.net (198.51.100.2) by mx.destination.com with ESMTP id m2; Mon, 8 Sep 2026 09:05:00 +0000",
        "from origin.sender.com (203.0.113.50) by relay.example.net with ESMTP id m1; Mon, 8 Sep 2026 09:00:00 +0000"
    ]
    analysis = RelayReconstructorService.reconstruct_relay_path(received)

    # Header order: index 0 is hop 1
    assert analysis.header_order_hops[0].from_host == "relay.example.net"
    assert analysis.header_order_hops[1].from_host == "origin.sender.com"

    # Transmission order: hop 1 is origin (bottom header in received list)
    assert analysis.transmission_order_hops[0].from_host == "origin.sender.com"
    assert analysis.transmission_order_hops[0].from_ip == "203.0.113.50"
    assert analysis.transmission_order_hops[1].from_host == "relay.example.net"

    # Earliest observable node must pick origin hop (203.0.113.50)
    assert analysis.earliest_observable_node.earliest_observable_ip == "203.0.113.50"


def test_missing_ip():
    received = [
        "from mail.example.org by mail.example.net with ESMTP id 123; Sun, 7 Sep 2026 10:00:00 +0000"
    ]
    analysis = RelayReconstructorService.reconstruct_relay_path(received)
    hop = analysis.header_order_hops[0]
    assert hop.from_host == "mail.example.org"
    assert hop.from_ip is None
    assert analysis.earliest_observable_node.earliest_observable_ip is None


def test_ipv6_hop():
    received = [
        "from mail.example.com ([IPv6:2001:db8::1]) by mx.google.com with ESMTPS id abc for <target@example.com>; Mon, 08 Sep 2026 12:00:00 -0000"
    ]
    analysis = RelayReconstructorService.reconstruct_relay_path(received)
    hop = analysis.header_order_hops[0]
    assert hop.from_ip == "2001:db8::1"
    assert analysis.earliest_observable_node.earliest_observable_ip == "2001:db8::1"


def test_ipv6_various_formats():
    # 1. Bracketed without 'IPv6:' prefix (standard Google/Postfix/M365 style)
    r1 = "from mail-pj1-x230.google.com (mail-pj1-x230.google.com [2607:f8b0:4864:20::230]) by mx.dest.com; Mon, 8 Sep 2026 10:00:00 +0000"
    # 2. Standalone IPv6 in from clause
    r2 = "from 2001:db8:85a3::8a2e:370:7334 by mx.dest.com; Mon, 8 Sep 2026 09:59:00 +0000"
    # 3. Parenthesized IPv6
    r3 = "from relay.domain.com (2a00:1450:400c:c0b::22f) by mx.dest.com; Mon, 8 Sep 2026 09:58:00 +0000"

    analysis = RelayReconstructorService.reconstruct_relay_path([r1, r2, r3])
    assert analysis.header_order_hops[0].from_ip == "2607:f8b0:4864:20::230"
    assert analysis.header_order_hops[1].from_ip == "2001:db8:85a3::8a2e:370:7334"
    assert analysis.header_order_hops[2].from_ip == "2a00:1450:400c:c0b::22f"
    # Earliest node should be from the bottom hop (r3)
    assert analysis.earliest_observable_node.earliest_observable_ip == "2a00:1450:400c:c0b::22f"



def test_malformed_received_header():
    received = [
        "Received: non-standard gibberish without semicolon or standard keywords"
    ]
    analysis = RelayReconstructorService.reconstruct_relay_path(received)
    assert len(analysis.header_order_hops) == 1
    hop = analysis.header_order_hops[0]
    assert hop.raw == received[0]
    assert hop.parser_confidence in ("low", "medium")


def test_mixed_private_public_chain():
    # Transmission order: internal LAN hop (192.168.1.10) -> public relay (198.51.100.99) -> destination MX (198.51.100.1)
    received = [
        "from mx.edge.com (198.51.100.1) by dest.internal with ESMTP; Mon, 8 Sep 2026 10:02:00 +0000",
        "from public.relay.com (198.51.100.99) by mx.edge.com with ESMTP; Mon, 8 Sep 2026 10:01:00 +0000",
        "from internal.pc.local (192.168.1.10) by public.relay.com with HTTP; Mon, 8 Sep 2026 10:00:00 +0000"
    ]
    analysis = RelayReconstructorService.reconstruct_relay_path(received)

    # Transmission order hop 1 is internal (192.168.1.10), which is private.
    # Earliest observable public IP must skip 192.168.1.10 and pick 198.51.100.99 from hop 2.
    node = analysis.earliest_observable_node
    assert node.earliest_observable_ip == "198.51.100.99"
    assert node.from_host == "public.relay.com"


def test_duplicate_hosts():
    received = [
        "from mail.example.com (198.51.100.5) by mail.example.com (198.51.100.6) with ESMTP; Sun, 7 Sep 2026 10:00:00 +0000"
    ]
    analysis = RelayReconstructorService.reconstruct_relay_path(received)
    hop = analysis.header_order_hops[0]
    assert hop.from_host == "mail.example.com"
    assert hop.by_host == "mail.example.com"
    assert hop.from_ip == "198.51.100.5"
    assert hop.by_ip == "198.51.100.6"
