from fastapi.testclient import TestClient
from ipsecguard.api.main import app
from ipsecguard.tunnel.peer import IPsecPeerNode


def test_sniffer_api_lifecycle():
    client = TestClient(app)
    status_resp = client.get("/api/sniffer/status")
    assert status_resp.status_code == 200
    assert "is_running" in status_resp.json()


def test_peer_tunnel_node():
    node_a = IPsecPeerNode(bind_port=8991)
    node_b = IPsecPeerNode(bind_port=8992)

    try:
        # Start listeners
        res_b = node_b.start_listener(port=8992)
        assert res_b["status"] == "listening"

        res_a = node_a.start_listener(port=8991)
        assert res_a["status"] == "listening"

        # Initiate handshake from A to B
        connect_res = node_a.initiate_tunnel(peer_host="127.0.0.1", peer_port=8992, cipher_preset="AES-256-GCM")
        assert connect_res["status"] == "connected"

        # Send encrypted ESP message
        send_res = node_a.send_secure_payload("Hello IPsecGuard Secure Tunnel!")
        assert send_res["status"] == "transmitted"
        assert send_res["seq"] == 1
        assert "ciphertext_hex" in send_res

        # Verify audit of live tunnel packets
        audit_result = node_a.audit_live_tunnel()
        assert audit_result.score > 0
        assert len(audit_result.findings) > 0
    finally:
        node_a.stop_listener()
        node_b.stop_listener()


def test_tunnel_api_endpoints():
    client = TestClient(app)
    status_resp = client.get("/api/tunnel/status")
    assert status_resp.status_code == 200
    assert "is_running" in status_resp.json()
