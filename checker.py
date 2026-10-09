import re
import time
import asyncio
import httpx
from typing import Optional, List, Dict, Any

_IP_REGEX = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
_GEOIP_CACHE: Dict[str, str] = {}

CHECK_TARGETS = [
    "http://api.ipify.org",
    "http://icanhazip.com",
    "http://checkip.amazonaws.com"
]

class ProxyNode:
    def __init__(self, raw_str: str, index: int = 0):
        self.id = index
        self.raw = raw_str.strip()
        self.protocol = "http"
        self.proto_specified = False
        self.host: Optional[str] = None
        self.port: Optional[int] = None
        self.user: Optional[str] = None
        self.password: Optional[str] = None

        self.node_type: str = "proxy"  # "proxy" or "surfshark"
        self.endpoint: Optional[str] = None
        self.pub_key: Optional[str] = None
        self.city: str = ""

        # Health info
        self.is_alive: Optional[bool] = None
        self.latency_ms: Optional[float] = None
        self.exit_ip: Optional[str] = None
        self.country: str = "Unknown"
        self.device_name: str = ""
        self.error: Optional[str] = None
        self.last_checked: Optional[float] = None

        # Dual-role lifecycle states
        self.status: str = "IDLE"  # Overall / Harvester status: IDLE, STARTING, RUNNING, STOPPED, ERROR
        self.relay_status: str = "STOPPED"  # STOPPED, RUNNING, ERROR
        self.relay_port: Optional[int] = None  # Inbound listening port (10001..N)

        self.pid: Optional[int] = None
        self.wp_pid: Optional[int] = None
        self.started_at: Optional[float] = None
        self.bytes_in: int = 0
        self.bytes_out: int = 0

        self._parse()

    def _parse(self):
        raw = self.raw
        if not raw or raw.startswith("#"):
            return
        if "#" in raw:
            raw = raw.split("#", 1)[0].strip()
        if "//" in raw and not re.match(r'^[a-zA-Z0-9]+://', raw):
            raw = raw.split("//", 1)[0].strip()
        raw = re.sub(r'^(?:LIVE\s+|\d+[\.\)]\s+)', '', raw, flags=re.I).strip()
        if not raw or raw.startswith("{"):
            return

        m_proto = re.match(r'^(socks5|socks4|https?)(?::/+|[;:]{1,2})(.*)$', raw, re.I)
        if m_proto:
            self.proto_specified = True
            scheme = m_proto.group(1).lower()
            self.protocol = "http" if scheme in ("http", "https") else scheme
            raw = m_proto.group(2).strip()
        else:
            self.proto_specified = False
            self.protocol = "http"

        def _is_valid_port(p_str: str) -> bool:
            return bool(p_str and p_str.isdigit() and 1 <= int(p_str) <= 65535)

        def _is_ip_or_domain(s: str) -> bool:
            if not s:
                return False
            if _IP_REGEX.match(s):
                return True
            if re.match(r'^\[?[0-9a-fA-F:]+\]?$', s) and ':' in s:
                return True
            if '.' in s and re.match(r'^[a-zA-Z0-9.-]+$', s):
                return True
            return False

        if "@" in raw:
            part1, part2 = raw.rsplit("@", 1)
            p1_sub = part1.split(":", 1) if ":" in part1 else [part1]
            p2_sub = part2.split(":", 1) if ":" in part2 else [part2]

            if len(p1_sub) == 2 and _is_ip_or_domain(p1_sub[0]) and _is_valid_port(p1_sub[1]) and not (_is_ip_or_domain(p2_sub[0]) and len(p2_sub) == 2 and _is_valid_port(p2_sub[1])):
                host_part, auth_part = part1, part2
            else:
                auth_part, host_part = part1, part2

            if ":" in auth_part:
                u, p = auth_part.split(":", 1)
                self.user = u.strip() or None
                self.password = p.strip() or None
            else:
                self.user = auth_part.strip() or None
                self.password = None

            if ":" in host_part:
                h, po = host_part.split(":", 1)
                po_clean = re.sub(r'[^\d]', '', po)
                if po_clean and (1 <= int(po_clean) <= 65535):
                    self.host = h.strip()
                    self.port = int(po_clean)
            return

        cleaned = raw.replace(";", ":").replace("|", ":").replace("\t", ":")
        tokens = [t.strip() for t in re.split(r'[:\s]+', cleaned) if t.strip()]

        if len(tokens) == 4:
            is_b_port = _is_valid_port(tokens[1])
            is_d_port = _is_valid_port(tokens[3])

            if is_b_port and not is_d_port:
                self.host = tokens[0]
                self.port = int(tokens[1])
                self.user = tokens[2]
                self.password = tokens[3]
            elif is_d_port and not is_b_port:
                self.host = tokens[2]
                self.port = int(tokens[3])
                self.user = tokens[0]
                self.password = tokens[1]
            elif is_b_port and is_d_port:
                if _is_ip_or_domain(tokens[0]) and not _is_ip_or_domain(tokens[2]):
                    self.host = tokens[0]
                    self.port = int(tokens[1])
                    self.user = tokens[2]
                    self.password = tokens[3]
                else:
                    self.host = tokens[2]
                    self.port = int(tokens[3])
                    self.user = tokens[0]
                    self.password = tokens[1]
        elif len(tokens) == 2:
            if _is_valid_port(tokens[1]):
                self.host = tokens[0]
                self.port = int(tokens[1])
        elif len(tokens) == 3:
            if _is_valid_port(tokens[1]):
                self.host = tokens[0]
                self.port = int(tokens[1])
                self.user = tokens[2]

    @property
    def is_valid(self) -> bool:
        return bool(self.host and self.port and 1 <= self.port <= 65535)

    def to_url(self, proto: Optional[str] = None) -> str:
        if not self.is_valid:
            return ""
        p = (proto or self.protocol or "http").lower()
        if "socks5" in p:
            proto_scheme = "socks5"
        elif "socks4" in p:
            proto_scheme = "socks4"
        else:
            proto_scheme = "http"

        if self.user and self.password:
            return f"{proto_scheme}://{self.user}:{self.password}@{self.host}:{self.port}"
        return f"{proto_scheme}://{self.host}:{self.port}"

    @property
    def proxy_url(self) -> str:
        return self.to_url()

    def update_device_name(self):
        c = self.country if self.country and self.country != "Unknown" else "Node"
        ip = self.exit_ip or self.host or "IP"
        nid = f"#{self.id}" if self.id else ""
        self.device_name = f"{c} - {ip} {nid}".strip()

    def to_dict(self, include_password: bool = False) -> Dict[str, Any]:
        uptime_sec = round(time.time() - self.started_at) if (self.status == "RUNNING" and self.started_at) else 0
        d = {
            "id": self.id,
            "node_type": self.node_type,
            "raw": self.raw,
            "protocol": self.protocol.upper(),
            "proto_specified": self.proto_specified,
            "host": self.host,
            "port": self.port,
            "user": self.user,
            "has_auth": bool(self.user and self.password),
            "is_alive": self.is_alive,
            "latency_ms": self.latency_ms,
            "exit_ip": self.exit_ip or self.host,
            "country": self.country,
            "city": self.city,
            "endpoint": self.endpoint,
            "device_name": self.device_name or f"Node-{self.id}",
            "status": self.status,
            "relay_status": self.relay_status,
            "relay_port": self.relay_port,
            "pid": self.pid,
            "uptime_seconds": uptime_sec,
            "bytes_in": self.bytes_in,
            "bytes_out": self.bytes_out,
            "error": self.error,
            "last_checked": self.last_checked
        }
        if include_password:
            d["password"] = self.password
        return d


def parse_proxies_text(content: str) -> List[ProxyNode]:
    nodes = []
    seen = set()
    idx = 1
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        p = ProxyNode(line, index=idx)
        if p.is_valid:
            key = (p.host, p.port, p.user, p.password)
            if key not in seen:
                seen.add(key)
                nodes.append(p)
                idx += 1
    return nodes


async def fetch_geoip_country(ip: str) -> str:
    global _GEOIP_CACHE
    if not ip or not _IP_REGEX.match(ip):
        return "Unknown"
    if ip in _GEOIP_CACHE:
        return _GEOIP_CACHE[ip]

    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            resp = await client.get(f"https://ipwho.is/{ip}")
            if resp.status_code == 200:
                data = resp.json()
                if data.get("success"):
                    code = data.get("country_code") or data.get("country") or "Unknown"
                    _GEOIP_CACHE[ip] = code
                    return code
    except Exception:
        pass
    return "Unknown"


async def check_single_proxy(proxy: ProxyNode, timeout: float = 5.0) -> ProxyNode:
    if not proxy.is_valid:
        proxy.is_alive = False
        proxy.error = "Format proxy tidak valid"
        return proxy

    if proxy.proto_specified:
        protocols_to_try = [proxy.protocol.lower()]
    else:
        protocols_to_try = ["http", "socks5"]

    last_err = "Gagal terkoneksi"

    for proto in protocols_to_try:
        proxy_url = proxy.to_url(proto=proto)
        for target_url in CHECK_TARGETS:
            t0 = time.time()
            try:
                async with httpx.AsyncClient(proxy=proxy_url, timeout=timeout, verify=False) as client:
                    resp = await client.get(target_url, timeout=timeout)
                    elapsed = (time.time() - t0) * 1000.0
                    proxy.last_checked = time.time()

                    if resp.status_code == 200:
                        text_ip = resp.text.strip()
                        if _IP_REGEX.match(text_ip):
                            proxy.is_alive = True
                            proxy.protocol = proto
                            proxy.latency_ms = round(elapsed, 1)
                            proxy.exit_ip = text_ip
                            proxy.error = None
                            proxy.country = await fetch_geoip_country(text_ip)
                            proxy.update_device_name()
                            return proxy
                        else:
                            last_err = "Respon bukan IP valid"
                    else:
                        last_err = f"HTTP {resp.status_code}"
            except (httpx.ConnectTimeout, httpx.ConnectError, httpx.ProxyError) as ce:
                proxy.last_checked = time.time()
                is_timeout = isinstance(ce, (httpx.ConnectTimeout, httpx.TimeoutException))
                last_err = f"Timeout ({timeout}s)" if is_timeout else "Proxy Connection Refused"
                break
            except Exception as e:
                proxy.last_checked = time.time()
                err_str = str(e).strip()
                if "timed out" in err_str.lower() or "timeout" in err_str.lower():
                    last_err = f"Timeout ({timeout}s)"
                    break
                else:
                    last_err = err_str[:35] or "Connection Failed"

    proxy.is_alive = False
    proxy.error = last_err
    proxy.update_device_name()
    return proxy


async def check_all_proxies(proxies: List[ProxyNode], max_concurrency: int = 20, timeout: float = 5.0) -> List[ProxyNode]:
    sem = asyncio.Semaphore(max_concurrency)

    async def _worker(p):
        async with sem:
            return await check_single_proxy(p, timeout=timeout)

    tasks = [_worker(p) for p in proxies]
    return await asyncio.gather(*tasks)
