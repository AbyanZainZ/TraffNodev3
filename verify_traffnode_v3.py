import asyncio
import socket
import json
import base64
from pathlib import Path
from checker import ProxyNode, parse_proxies_text
from surfshark import load_surfshark_servers, pick_surfshark_servers
from relay_engine import ProxyRelayPort, RelayManager
from supervisor import NodeSupervisor
from app import app, get_combined_nodes

def test_surfshark_pool():
    servers = load_surfshark_servers()
    assert len(servers) >= 900, f"Expected 900+ servers, found {len(servers)}"
    picked = pick_surfshark_servers(count=30, region="all")
    assert len(picked) == 30, f"Expected 30 picked servers, got {len(picked)}"
    ips = [s["endpoint"].split(":")[0] for s in picked]
    assert len(ips) == len(set(ips)), "Duplicate IP found in picked servers"
    print("[PASS] 1. Surfshark 925 servers loader & zero-duplicate picker verified.")

def test_proxy_parser():
    sample = """
    191.96.254.138:6185:windowsproxy001:win012345
    socks5://user:pass@31.59.20.176:6754
    http://31.58.9.4:6077
    """
    nodes = parse_proxies_text(sample)
    assert len(nodes) == 3, f"Expected 3 parsed nodes, got {len(nodes)}"
    assert nodes[0].host == "191.96.254.138" and nodes[0].port == 6185 and nodes[0].user == "windowsproxy001"
    assert nodes[1].protocol.lower() == "socks5" and nodes[1].host == "31.59.20.176"
    assert nodes[2].host == "31.58.9.4" and nodes[2].port == 6077
    d = nodes[0].to_dict()
    assert "relay_status" in d and "status" in d
    print("[PASS] 2. Checker multi-format proxy parser verified.")

async def test_relay_engine():
    # Test relay port listener and auth checking
    dummy_node = ProxyNode("127.0.0.1:8080:dummy:dummy", index=1)
    test_port = 19988
    relay = ProxyRelayPort(
        port=test_port,
        upstream=dummy_node,
        client_user="testuser",
        client_pass="testpass",
        bind_host="127.0.0.1"
    )
    await relay.start()
    assert relay.is_running is True

    # Connect client with wrong credentials
    reader, writer = await asyncio.open_connection("127.0.0.1", test_port)
    bad_req = (
        "CONNECT example.com:443 HTTP/1.1\r\n"
        "Host: example.com:443\r\n"
        "Proxy-Authorization: Basic " + base64.b64encode(b"wrong:creds").decode('ascii') + "\r\n\r\n"
    )
    writer.write(bad_req.encode('ascii'))
    await writer.drain()

    resp = await reader.read(200)
    assert b"407 Proxy Authentication Required" in resp, f"Expected 407, got {resp}"
    writer.close()
    await writer.wait_closed()

    await relay.stop()
    assert relay.is_running is False
    print("[PASS] 3. Relay Engine HTTP CONNECT auth verification verified.")

def test_antislop_ui():
    html_file = Path(__file__).resolve().parent / "static" / "index.html"
    assert html_file.exists(), "index.html missing"
    content = html_file.read_text(encoding="utf-8")
    # Verify no em dash character exists in UI text per R-02
    assert "—" not in content, "Em dash ('—') found in index.html (violates antislop R-02)"
    # Verify key interactive control IDs exist
    for btn_id in ["btn-start-hybrid", "btn-start-harvester-only", "btn-start-relay-only", "btn-stop-all", "btn-purge-error", "btn-export-relay"]:
        assert f'id="{btn_id}"' in content, f"Button {btn_id} missing in index.html"
    print("[PASS] 4. Antislop compliance check (no em-dashes, full controls) verified.")

def test_supervisor_simulated():
    sup = NodeSupervisor()
    node = ProxyNode("1.1.1.1:8080", index=99)
    ok = sup.start_harvester(node, token="test_token")
    assert ok is True
    assert node.status == "RUNNING"
    sup.stop_harvester(node)
    assert node.status == "STOPPED"
    print("[PASS] 5. Process supervisor lifecycle verified.")

async def main():
    print("==================================================================")
    print("  TRAFFNODE V3: COMPREHENSIVE AUTOMATED VERIFICATION SUITE")
    print("==================================================================")
    test_surfshark_pool()
    test_proxy_parser()
    await test_relay_engine()
    test_antislop_ui()
    test_supervisor_simulated()
    print("==================================================================")
    print("  ALL 5 VERIFICATION TEST SUITES PASSED PERFECTLY!")
    print("==================================================================")

if __name__ == "__main__":
    asyncio.run(main())
