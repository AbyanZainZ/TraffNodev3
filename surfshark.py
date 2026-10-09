import json
import random
from pathlib import Path
from typing import List, Dict, Any, Optional

SERVERS_FILE = Path(__file__).resolve().parent / "surfshark_servers.json"

REGION_COUNTRIES = {
    "us": ["US"],
    "eu": [
        "GB", "DE", "FR", "NL", "IT", "ES", "CH", "SE", "NO", "DK",
        "FI", "PL", "CZ", "AT", "BE", "IE", "PT", "RO", "HU", "GR"
    ],
    "asia": ["SG", "JP", "KR", "HK", "TW", "IN", "MY", "TH", "VN", "ID", "PH"],
    "latam": ["BR", "MX", "AR", "CL", "CO", "PE"],
    "africa": ["ZA", "NG", "EG", "KE"]
}

def load_surfshark_servers() -> List[Dict[str, Any]]:
    # Load dedicated physical WireGuard endpoints from local database
    if not SERVERS_FILE.exists():
        return []
    try:
        with open(SERVERS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data if isinstance(data, list) else []
    except Exception:
        return []

def get_servers_by_region(region: str = "all") -> List[Dict[str, Any]]:
    all_servers = load_surfshark_servers()
    if not all_servers:
        return []

    r = (region or "all").lower().strip()
    if r == "all":
        return all_servers

    allowed_codes = set(REGION_COUNTRIES.get(r, []))
    if not allowed_codes:
        return all_servers

    return [s for s in all_servers if s.get("country", "").upper() in allowed_codes]

def pick_surfshark_servers(count: int = 50, region: str = "all") -> List[Dict[str, Any]]:
    pool = get_servers_by_region(region)
    if not pool:
        pool = load_surfshark_servers()
    if not pool:
        return []

    # Deduplicate by endpoint IP to avoid duplicate IP penalties on networks
    unique_pool = []
    seen_ips = set()
    for s in pool:
        ep = s.get("endpoint", "")
        ip = ep.split(":")[0] if ":" in ep else ep
        if ip and ip not in seen_ips:
            seen_ips.add(ip)
            unique_pool.append(s)

    random.shuffle(unique_pool)
    return unique_pool[:min(count, len(unique_pool))]


_ENDPOINT_PUBKEY_CACHE: Optional[Dict[str, str]] = None

def get_endpoint_pubkey_map() -> Dict[str, str]:
    global _ENDPOINT_PUBKEY_CACHE
    if _ENDPOINT_PUBKEY_CACHE is None:
        servers = load_surfshark_servers()
        _ENDPOINT_PUBKEY_CACHE = {}
        for s in servers:
            ep = s.get("endpoint", "")
            pk = s.get("pubkey") or s.get("pub_key") or ""
            if ep and pk:
                _ENDPOINT_PUBKEY_CACHE[ep.strip()] = pk.strip()
    return _ENDPOINT_PUBKEY_CACHE

def find_pubkey_for_endpoint(endpoint: Optional[str]) -> Optional[str]:
    if not endpoint:
        return None
    ep_map = get_endpoint_pubkey_map()
    return ep_map.get(endpoint.strip())

