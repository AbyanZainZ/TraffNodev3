import os
import json
import time
import socket
import asyncio
from pathlib import Path
from contextlib import asynccontextmanager
from typing import Dict, Any, List, Optional

import secrets
import base64
from fastapi import FastAPI, HTTPException, BackgroundTasks, Request, Response, status
from fastapi.responses import HTMLResponse, PlainTextResponse, FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
import psutil

from checker import ProxyNode, parse_proxies_text, check_all_proxies
from surfshark import pick_surfshark_servers, load_surfshark_servers, find_pubkey_for_endpoint
from supervisor import NodeSupervisor
from relay_engine import RelayManager
from bandwidth import BandwidthTracker, format_bytes

BASE_DIR = Path(__file__).resolve().parent
CONFIG_PATH = BASE_DIR / "config.json"
PROXIES_PATH = BASE_DIR / "proxies.txt"
NODES_PATH = BASE_DIR / "nodes.json"
STATIC_DIR = BASE_DIR / "static"

DEFAULT_CONFIG = {
    "host": "0.0.0.0",
    "dashboard_port": 80,
    "dashboard_auth_enabled": True,
    "dashboard_username": "admin",
    "dashboard_password": "admin123",
    "traff_token": "",
    "surfshark_private_key": "",
    "surfshark_region": "all",
    "surfshark_node_count": 50,
    "surfshark_start_port": 21000,
    "relay_start_port": 10001,
    "relay_client_user": "gemini",
    "relay_client_pass": "gemini",
    "check_timeout": 4.0,
    "max_instances": 1000,
    "auto_heal_interval_seconds": 30,
    "auto_start_on_boot": False
}

ACTIVE_SESSIONS: Dict[str, float] = {}

class ConfigUpdateRequest(BaseModel):
    traff_token: Optional[str] = None
    dashboard_port: Optional[int] = None
    dashboard_auth_enabled: Optional[bool] = None
    dashboard_username: Optional[str] = None
    dashboard_password: Optional[str] = None
    max_instances: Optional[int] = None
    surfshark_private_key: Optional[str] = None
    surfshark_region: Optional[str] = None
    surfshark_node_count: Optional[int] = None
    surfshark_start_port: Optional[int] = None
    relay_start_port: Optional[int] = None
    relay_client_user: Optional[str] = None
    relay_client_pass: Optional[str] = None

class LoginRequest(BaseModel):
    username: str
    password: str

class AuthUpdateRequest(BaseModel):
    auth_enabled: Optional[bool] = None
    username: Optional[str] = None
    password: Optional[str] = None

class CheckRequest(BaseModel):
    remove_dead: Optional[bool] = False
    raw_text: Optional[str] = None

class ProxiesUpdateRequest(BaseModel):
    raw_text: str
    mode: Optional[str] = "replace"

class SurfsharkGenerateRequest(BaseModel):
    region: str = "all"
    count: int = 50
    start_port: int = 21000
    mode: str = "replace"


def load_config() -> dict:
    if CONFIG_PATH.exists():
        try:
            with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                cfg = json.load(f)
                return {**DEFAULT_CONFIG, **cfg}
        except Exception:
            pass
    return DEFAULT_CONFIG.copy()

def save_config(cfg: dict):
    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)

def load_proxies_file() -> str:
    if PROXIES_PATH.exists():
        with open(PROXIES_PATH, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()
    return ""

def save_proxies_file(content: str):
    with open(PROXIES_PATH, "w", encoding="utf-8") as f:
        f.write(content)

def save_nodes_file(nodes_list: List[ProxyNode]):
    try:
        data = [n.to_dict(include_password=True) for n in nodes_list]
        with open(NODES_PATH, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
    except Exception as e:
        print(f"[TraffNode V3] Error saving nodes.json: {e}")

def load_nodes_file() -> List[ProxyNode]:
    if NODES_PATH.exists():
        try:
            with open(NODES_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
            loaded: List[ProxyNode] = []
            for item in data:
                node = ProxyNode(item.get("raw", ""), index=item.get("id", len(loaded) + 1))
                if item.get("password"):
                    node.password = item.get("password")
                node.node_type = item.get("node_type", "proxy")
                node.protocol = item.get("protocol", "HTTP").lower()
                node.proto_specified = item.get("proto_specified", False)
                node.host = item.get("host")
                node.port = item.get("port")
                node.user = item.get("user")
                node.endpoint = item.get("endpoint") or ""
                node.pub_key = item.get("pub_key") or item.get("pubkey") or ""
                if node.node_type == "surfshark" and not node.pub_key and node.endpoint:
                    node.pub_key = find_pubkey_for_endpoint(node.endpoint) or ""
                node.city = item.get("city", "")
                node.country = item.get("country", "Unknown")
                node.exit_ip = item.get("exit_ip")
                node.device_name = item.get("device_name", "")
                node.status = "IDLE"
                node.relay_status = "STOPPED"
                node.relay_port = item.get("relay_port")
                node.is_alive = item.get("is_alive", True if node.node_type == "surfshark" else None)
                node.latency_ms = item.get("latency_ms")
                if node.node_type == "proxy" and node.is_alive is False:
                    continue
                loaded.append(node)
            return loaded
        except Exception as e:
            print(f"[TraffNode V3] Error loading nodes.json: {e}")
    return []

_cached_public_ip = None

def get_server_ip() -> str:
    global _cached_public_ip
    if _cached_public_ip:
        return _cached_public_ip

    import urllib.request
    endpoints = [
        "https://api.ipify.org",
        "https://ifconfig.me/ip",
        "https://icanhazip.com",
        "https://checkip.amazonaws.com"
    ]
    for url in endpoints:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "curl/7.88.1"})
            with urllib.request.urlopen(req, timeout=2.0) as resp:
                detected = resp.read().decode("utf-8").strip()
                if detected and not detected.startswith(("10.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.", "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.", "192.168.", "127.")):
                    _cached_public_ip = detected
                    return detected
        except Exception:
            pass

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.5)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


config = load_config()
relay_manager = RelayManager(
    start_port=config.get("relay_start_port", 10001),
    client_user=config.get("relay_client_user", "gemini"),
    client_pass=config.get("relay_client_pass", "gemini")
)
supervisor = NodeSupervisor(relay_manager=relay_manager)
bandwidth_tracker = BandwidthTracker()

surfshark_nodes: List[ProxyNode] = []
custom_proxy_nodes: List[ProxyNode] = []
is_checking = False

def get_combined_nodes() -> List[ProxyNode]:
    return surfshark_nodes + custom_proxy_nodes

def find_node_by_id(node_id: int) -> Optional[ProxyNode]:
    for n in surfshark_nodes:
        if n.id == node_id:
            return n
    for n in custom_proxy_nodes:
        if n.id == node_id:
            return n
    return None

def is_authenticated(request: Request) -> bool:
    if not config.get("dashboard_auth_enabled", True):
        return True

    token = request.cookies.get("tn_session")
    if token and token in ACTIVE_SESSIONS:
        if time.time() < ACTIVE_SESSIONS[token]:
            return True
        else:
            ACTIVE_SESSIONS.pop(token, None)

    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        b_tok = auth_header[7:].strip()
        if b_tok in ACTIVE_SESSIONS:
            if time.time() < ACTIVE_SESSIONS[b_tok]:
                return True
            else:
                ACTIVE_SESSIONS.pop(b_tok, None)
    elif auth_header.startswith("Basic "):
        try:
            raw = base64.b64decode(auth_header[6:].strip()).decode("utf-8")
            u, p = raw.split(":", 1)
            cfg_u = str(config.get("dashboard_username", "admin"))
            cfg_p = str(config.get("dashboard_password", "admin123"))
            if u == cfg_u and p == cfg_p:
                return True
        except Exception:
            pass

    return False

_check_cancel_event: Optional[asyncio.Event] = None

check_state = {
    "is_checking": False,
    "cancel_requested": False,
    "remove_dead": False,
    "total": 0,
    "done": 0,
    "alive": 0,
    "dead": 0,
    "current_target": "",
    "last_result": None
}

async def run_health_check_task(remove_dead: bool = False, raw_text: Optional[str] = None):
    global custom_proxy_nodes, _check_cancel_event
    if check_state["is_checking"]:
        return

    # Parse candidates from raw_text, proxies.txt, or existing custom_proxy_nodes
    candidates_text = ""
    if raw_text is not None and raw_text.strip():
        candidates_text = raw_text.strip()
    else:
        candidates_text = load_proxies_file().strip()

    candidates: List[ProxyNode] = []
    if candidates_text:
        candidates = parse_proxies_text(candidates_text)
    elif custom_proxy_nodes:
        candidates = [ProxyNode(n.raw) for n in custom_proxy_nodes]

    if not candidates:
        check_state["is_checking"] = False
        check_state["last_result"] = "Tidak ada proxy untuk dicek (daftar proxy kosong)."
        return

    # User requirement:
    # "proxy yang live masuk ke daftar yang di bawah"
    # "proxy yang masih checking , gak perlu di masukin ke bawah , bikin lag doang"
    # Candidates are kept in checking queue only. custom_proxy_nodes is cleared for live-only promotion.
    supervisor.stop_filtered_harvesters(custom_proxy_nodes, "proxy")
    custom_proxy_nodes = []
    save_nodes_file(get_combined_nodes())

    _check_cancel_event = asyncio.Event()
    check_state["is_checking"] = True
    check_state["cancel_requested"] = False
    check_state["remove_dead"] = remove_dead
    check_state["total"] = len(candidates)
    check_state["done"] = 0
    check_state["alive"] = 0
    check_state["dead"] = 0
    check_state["current_target"] = ""
    check_state["last_result"] = None

    live_nodes_lock = asyncio.Lock()
    next_node_id = 1001

    async def _on_proxy_live(node: ProxyNode):
        nonlocal next_node_id
        async with live_nodes_lock:
            node.id = next_node_id
            next_node_id += 1
            node.node_type = "proxy"
            node.status = "IDLE"
            node.relay_status = "STOPPED"
            custom_proxy_nodes.append(node)
            # Periodic persist so newly discovered live nodes appear in API in real-time
            if len(custom_proxy_nodes) % 5 == 0 or len(custom_proxy_nodes) <= 10:
                save_nodes_file(get_combined_nodes())
                lines = [p.to_url() for p in custom_proxy_nodes]
                save_proxies_file("\n".join(lines))

    def _on_prog(done, total, alive, dead, current_target=""):
        check_state["done"] = done
        check_state["total"] = total
        check_state["alive"] = alive
        check_state["dead"] = dead
        check_state["current_target"] = current_target

    try:
        checked_proxies = await check_all_proxies(
            candidates,
            max_concurrency=60,
            timeout=config.get("check_timeout", 3.5),
            progress_callback=_on_prog,
            on_live_callback=_on_proxy_live,
            cancel_event=_check_cancel_event
        )

        was_cancelled = check_state["cancel_requested"] or (_check_cancel_event and _check_cancel_event.is_set())

        # Final save of live proxies
        lines = [p.to_url() for p in custom_proxy_nodes]
        save_proxies_file("\n".join(lines))
        save_nodes_file(get_combined_nodes())

        if was_cancelled:
            check_state["last_result"] = f"Pengecekan dihentikan: {check_state['done']} dari {check_state['total']} diperiksa. ({len(custom_proxy_nodes)} Proxy Live berhasil masuk ke daftar bawah)."
        else:
            check_state["last_result"] = f"Pengecekan selesai: {check_state['total']} proxy diperiksa. {len(custom_proxy_nodes)} Proxy Live masuk ke daftar bawah ({check_state['dead']} proxy mati dibuang)."

    finally:
        check_state["is_checking"] = False
        check_state["cancel_requested"] = False
        _check_cancel_event = None
        save_nodes_file(get_combined_nodes())
        lines = [p.to_url() for p in custom_proxy_nodes]
        save_proxies_file("\n".join(lines))

async def auto_supervisor_loop():
    while True:
        try:
            await asyncio.sleep(config.get("auto_heal_interval_seconds", 30))
            token = config.get("traff_token", "")
            privkey = config.get("surfshark_private_key", "")
            all_nodes = get_combined_nodes()
            if token and all_nodes:
                supervisor.auto_heal_check(all_nodes, token, surfshark_privkey=privkey)
                save_nodes_file(all_nodes)
                for n in all_nodes:
                    if n.pid:
                        bandwidth_tracker.update_proc_traffic(n.pid, n)
        except Exception:
            pass


@asynccontextmanager
async def lifespan(app: FastAPI):
    global surfshark_nodes, custom_proxy_nodes
    STATIC_DIR.mkdir(parents=True, exist_ok=True)
    loaded_all = load_nodes_file()
    surfshark_nodes = [n for n in loaded_all if getattr(n, "node_type", "") == "surfshark"]
    custom_proxy_nodes = [n for n in loaded_all if getattr(n, "node_type", "proxy") == "proxy"]

    # Load master proxies text if custom proxy list was empty
    if not custom_proxy_nodes:
        raw_px = load_proxies_file()
        if raw_px:
            parsed = parse_proxies_text(raw_px)
            for idx, p in enumerate(parsed):
                p.id = 1001 + idx
                p.node_type = "proxy"
            custom_proxy_nodes = parsed
            save_nodes_file(get_combined_nodes())

    asyncio.create_task(auto_supervisor_loop())
    yield
    supervisor.stop_all_harvesters(get_combined_nodes())
    await relay_manager.stop_all()


app = FastAPI(title="TraffNode V3 Cockpit", lifespan=lifespan)
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.middleware("http")
async def auth_middleware(request: Request, call_next):
    path = request.url.path
    if (
        path == "/"
        or path.startswith("/static")
        or path == "/favicon.ico"
        or path in ("/api/login", "/api/logout", "/api/auth/status")
    ):
        response = await call_next(request)
        response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
        return response

    if not config.get("dashboard_auth_enabled", True):
        return await call_next(request)

    if is_authenticated(request):
        return await call_next(request)

    return JSONResponse(
        status_code=401,
        content={"detail": "Unauthorized. Login diperlukan untuk mengakses TraffNode V3.", "authenticated": False}
    )


@app.get("/api/auth/status")
async def get_auth_status(request: Request):
    auth_enabled = bool(config.get("dashboard_auth_enabled", True))
    if not auth_enabled:
        return {"auth_enabled": False, "logged_in": True, "username": "admin"}
    logged_in = is_authenticated(request)
    u = config.get("dashboard_username", "admin") if logged_in else None
    return {"auth_enabled": True, "logged_in": logged_in, "username": u}


@app.post("/api/login")
async def do_login(payload: LoginRequest, response: Response):
    cfg_user = str(config.get("dashboard_username", "admin"))
    cfg_pass = str(config.get("dashboard_password", "admin123"))

    if payload.username == cfg_user and payload.password == cfg_pass:
        token = secrets.token_hex(32)
        ACTIVE_SESSIONS[token] = time.time() + (86400 * 30)
        response.set_cookie(
            key="tn_session",
            value=token,
            max_age=86400 * 30,
            httponly=True,
            samesite="lax",
            secure=False
        )
        return {"success": True, "token": token, "username": cfg_user, "message": "Login berhasil."}

    return JSONResponse(status_code=401, content={"success": False, "detail": "Username atau password salah."})


@app.post("/api/logout")
async def do_logout(request: Request, response: Response):
    token = request.cookies.get("tn_session")
    if token and token in ACTIVE_SESSIONS:
        ACTIVE_SESSIONS.pop(token, None)
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        b_tok = auth_header[7:].strip()
        ACTIVE_SESSIONS.pop(b_tok, None)
    response.delete_cookie(key="tn_session")
    return {"success": True, "message": "Berhasil logout."}


@app.post("/api/auth/update")
async def update_auth_credentials(payload: AuthUpdateRequest, response: Response):
    global config
    if payload.auth_enabled is not None:
        config["dashboard_auth_enabled"] = payload.auth_enabled
    if payload.username and payload.username.strip():
        config["dashboard_username"] = payload.username.strip()
    if payload.password and payload.password.strip():
        config["dashboard_password"] = payload.password.strip()

    save_config(config)

    token = secrets.token_hex(32)
    ACTIVE_SESSIONS[token] = time.time() + (86400 * 30)
    response.set_cookie(
        key="tn_session",
        value=token,
        max_age=86400 * 30,
        httponly=True,
        samesite="lax",
        secure=False
    )
    return {
        "success": True,
        "token": token,
        "username": config.get("dashboard_username"),
        "auth_enabled": config.get("dashboard_auth_enabled"),
        "message": "Kredensial dashboard berhasil diperbarui."
    }


@app.get("/", response_class=HTMLResponse)
async def serve_index():
    index_file = STATIC_DIR / "index.html"
    if index_file.exists():
        with open(index_file, "r", encoding="utf-8") as f:
            return f.read()
    return "<h1>TraffNode V3 Cockpit Dashboard</h1><p>Frontend static/index.html is loading...</p>"


@app.get("/api/status")
async def get_system_status():
    all_nodes = get_combined_nodes()
    harvester_running = sum(1 for n in all_nodes if n.status == "RUNNING")
    harvester_starting = sum(1 for n in all_nodes if n.status == "STARTING")

    relay_running = len(relay_manager.ports)
    relay_stats = relay_manager.get_all_stats()
    relay_active_conns = sum(r.get("active_conns", 0) for r in relay_stats)
    relay_bytes_in = sum(r.get("bytes_in", 0) for r in relay_stats)
    relay_bytes_out = sum(r.get("bytes_out", 0) for r in relay_stats)

    ss_nodes = [n for n in surfshark_nodes]
    ss_harvester_running = sum(1 for n in ss_nodes if n.status == "RUNNING")
    ss_relay_running = sum(1 for n in ss_nodes if n.relay_status == "RUNNING")

    px_nodes = [n for n in custom_proxy_nodes]
    px_harvester_running = sum(1 for n in px_nodes if n.status == "RUNNING")
    px_relay_running = sum(1 for n in px_nodes if n.relay_status == "RUNNING")
    px_alive = sum(1 for n in px_nodes if n.is_alive is True)
    px_dead = sum(1 for n in px_nodes if n.is_alive is False)

    sys_bw = bandwidth_tracker.get_system_bandwidth()
    cpu_percent = psutil.cpu_percent(interval=None)
    ram = psutil.virtual_memory()

    return {
        "status": "online",
        "version": "3.0.0",
        "server_ip": get_server_ip(),
        "config": {
            "traff_token": config.get("traff_token", ""),
            "surfshark_private_key": config.get("surfshark_private_key", ""),
            "surfshark_region": config.get("surfshark_region", "all"),
            "surfshark_node_count": config.get("surfshark_node_count", 50),
            "surfshark_start_port": config.get("surfshark_start_port", 21000),
            "relay_start_port": config.get("relay_start_port", 10001),
            "relay_client_user": config.get("relay_client_user", "gemini"),
            "relay_client_pass": config.get("relay_client_pass", "gemini"),
            "dashboard_port": config.get("dashboard_port", 80),
            "dashboard_auth_enabled": config.get("dashboard_auth_enabled", True),
            "dashboard_username": config.get("dashboard_username", "admin")
        },
        "check_state": check_state,
        "metrics": {
            "total_nodes": len(all_nodes),
            "harvester_running": harvester_running,
            "harvester_starting": harvester_starting,
            "relay_running": relay_running,
            "relay_active_conns": relay_active_conns,
            "relay_traffic_in": format_bytes(relay_bytes_in),
            "relay_traffic_out": format_bytes(relay_bytes_out),
            "is_starting_batch": supervisor.is_starting_batch,
            "surfshark_total": len(ss_nodes),
            "surfshark_harvester_running": ss_harvester_running,
            "surfshark_relay_running": ss_relay_running,
            "proxy_total": len(px_nodes),
            "proxy_alive": px_alive,
            "proxy_dead": px_dead,
            "proxy_harvester_running": px_harvester_running,
            "proxy_relay_running": px_relay_running,
            "bandwidth": {
                "total_in": sys_bw.get("total_recv_bytes", 0),
                "total_out": sys_bw.get("total_sent_bytes", 0),
                "formatted_in": format_bytes(sys_bw.get("total_recv_bytes", 0)),
                "formatted_out": format_bytes(sys_bw.get("total_sent_bytes", 0)),
                "speed_up_bps": sys_bw.get("speed_up_bps", 0),
                "speed_down_bps": sys_bw.get("speed_down_bps", 0)
            }
        },
        "system": {
            "cpu_percent": cpu_percent,
            "ram_percent": ram.percent,
            "ram_used_mb": round(ram.used / (1024 * 1024)),
            "ram_total_mb": round(ram.total / (1024 * 1024))
        },
        "nodes": [n.to_dict() for n in all_nodes]
    }


@app.post("/api/config")
async def update_config_endpoint(payload: ConfigUpdateRequest):
    global config
    if payload.traff_token is not None and payload.traff_token.strip():
        config["traff_token"] = payload.traff_token.strip()
    if payload.dashboard_port is not None:
        config["dashboard_port"] = max(1, min(65535, payload.dashboard_port))
    if payload.dashboard_auth_enabled is not None:
        config["dashboard_auth_enabled"] = payload.dashboard_auth_enabled
    if payload.dashboard_username is not None and payload.dashboard_username.strip():
        config["dashboard_username"] = payload.dashboard_username.strip()
    if payload.dashboard_password is not None and payload.dashboard_password.strip():
        config["dashboard_password"] = payload.dashboard_password.strip()
    if payload.surfshark_private_key is not None and payload.surfshark_private_key.strip():
        config["surfshark_private_key"] = payload.surfshark_private_key.strip()
    if payload.surfshark_region is not None:
        config["surfshark_region"] = payload.surfshark_region
    if payload.surfshark_node_count is not None:
        config["surfshark_node_count"] = payload.surfshark_node_count
    if payload.surfshark_start_port is not None:
        config["surfshark_start_port"] = payload.surfshark_start_port
    if payload.relay_start_port is not None:
        config["relay_start_port"] = payload.relay_start_port
        relay_manager.start_port = payload.relay_start_port
    if payload.relay_client_user is not None:
        config["relay_client_user"] = payload.relay_client_user.strip()
        relay_manager.client_user = config["relay_client_user"]
    if payload.relay_client_pass is not None:
        config["relay_client_pass"] = payload.relay_client_pass.strip()
        relay_manager.client_pass = config["relay_client_pass"]

    save_config(config)
    return {"success": True, "config": config, "message": "Konfigurasi V3 berhasil disimpan."}


@app.post("/api/surfshark/generate")
async def generate_surfshark_pool(payload: SurfsharkGenerateRequest):
    global surfshark_nodes
    region = payload.region or "all"
    count = max(1, min(925, payload.count))
    start_port = max(1024, min(60000, payload.start_port))

    picked = pick_surfshark_servers(count=count, region=region)
    if not picked:
        raise HTTPException(status_code=400, detail="Tidak ada server Surfshark yang sesuai dengan wilayah ini.")

    if payload.mode == "replace":
        supervisor.stop_filtered_harvesters(surfshark_nodes, "surfshark")
        surfshark_nodes = []

    new_ss_nodes = []
    base_id = 1 if payload.mode == "replace" else (max([n.id for n in surfshark_nodes] + [0]) + 1)
    for idx, s in enumerate(picked):
        node = ProxyNode("", index=base_id + idx)
        node.node_type = "surfshark"
        node.protocol = "socks5"
        node.host = "127.0.0.1"
        node.port = start_port + idx
        node.endpoint = s.get("endpoint", "")
        node.pub_key = s.get("pubkey") or s.get("pub_key") or find_pubkey_for_endpoint(node.endpoint) or ""
        node.city = s.get("city", "")
        node.country = s.get("country", region.upper())
        node.update_device_name()
        node.is_alive = True
        node.status = "IDLE"
        node.relay_status = "STOPPED"
        new_ss_nodes.append(node)

    surfshark_nodes.extend(new_ss_nodes)
    save_nodes_file(get_combined_nodes())

    return {
        "success": True,
        "count": len(picked),
        "surfshark_total": len(surfshark_nodes),
        "total_nodes": len(get_combined_nodes()),
        "message": f"Berhasil men-generate {len(picked)} node Surfshark VPN ({region.upper()})."
    }


@app.get("/api/proxies/raw", response_class=PlainTextResponse)
async def get_raw_proxies():
    return load_proxies_file()


@app.post("/api/proxies")
async def update_proxies(payload: ProxiesUpdateRequest, bg_tasks: BackgroundTasks):
    save_proxies_file(payload.raw_text)
    parsed = parse_proxies_text(payload.raw_text)
    bg_tasks.add_task(run_health_check_task, remove_dead=True, raw_text=payload.raw_text)

    return {
        "success": True,
        "count": len(parsed),
        "proxy_total": len(custom_proxy_nodes),
        "total_nodes": len(get_combined_nodes()),
        "message": f"Daftar {len(parsed)} proxy diterima. Engine mulai memeriksa kesehatan (hanya proxy LIVE yang akan dimasukkan ke tabel bawah)."
    }


@app.post("/api/check")
async def trigger_check(bg_tasks: BackgroundTasks, payload: Optional[CheckRequest] = None):
    if check_state["is_checking"]:
        return {"success": False, "message": "Pengecekan proxy sedang berlangsung."}

    raw_text = payload.raw_text.strip() if (payload and payload.raw_text) else None
    remove_dead = bool(payload and payload.remove_dead)

    has_text = bool(raw_text and len(raw_text) > 0)
    txt_file = load_proxies_file().strip()

    if not has_text and not custom_proxy_nodes and not txt_file:
        return {
            "success": False,
            "message": "Daftar proxy kosong! Klik '💾 SIMPAN PROXY' atau tempel daftar proxy di textarea terlebih dahulu."
        }

    bg_tasks.add_task(run_health_check_task, remove_dead=remove_dead, raw_text=raw_text)
    msg = "Pengecekan proxy dimulai (otomatis hapus proxy mati)." if remove_dead else "Pengecekan kesehatan proxy dimulai."
    return {"success": True, "message": msg}


@app.post("/api/check/stop")
async def stop_check_endpoint():
    global _check_cancel_event
    if not check_state["is_checking"]:
        return {"success": False, "message": "Tidak ada pengecekan proxy yang sedang aktif."}
    check_state["cancel_requested"] = True
    if _check_cancel_event:
        _check_cancel_event.set()
    return {"success": True, "message": "Perintah STOP diterima. Pengecekan proxy sedang dihentikan..."}


@app.post("/api/proxies/purge-dead")
async def purge_dead_proxies():
    global custom_proxy_nodes
    # Keep only strictly verified LIVE proxies (is_alive is True)
    custom_proxy_nodes = [n for n in custom_proxy_nodes if n.is_alive is True and n.status != "ERROR"]
    removed = initial_count - len(custom_proxy_nodes)
    for idx, p in enumerate(custom_proxy_nodes):
        p.id = 1001 + idx
    lines = [p.to_url() for p in custom_proxy_nodes]
    save_proxies_file("\n".join(lines))
    save_nodes_file(get_combined_nodes())
    return {
        "success": True,
        "removed": removed,
        "remaining": len(custom_proxy_nodes),
        "message": f"Berhasil membersihkan {removed} proxy dead/unverified. Sisa {len(custom_proxy_nodes)} proxy LIVE aktif di tabel."
    }


# Harvester controls
@app.post("/api/harvester/start-all")
async def start_harvester_all():
    token = config.get("traff_token", "")
    privkey = config.get("surfshark_private_key", "")
    if not token:
        raise HTTPException(status_code=400, detail="Token TraffMonetizer belum diisi di konfigurasi.")
    all_nodes = get_combined_nodes()
    if not all_nodes:
        raise HTTPException(status_code=400, detail="Belum ada node yang siap dijalankan.")

    to_start = [n for n in all_nodes if n.status != "RUNNING" and (n.is_alive is not False and n.status != "ERROR")]
    if not to_start:
        raise HTTPException(status_code=400, detail="Tidak ada node aktif yang siap dijalankan (seluruh node dead atau sudah running).")

    for n in to_start:
        n.status = "STARTING"
    save_nodes_file(all_nodes)

    asyncio.create_task(
        supervisor.start_harvesters_staggered(
            to_start,
            token,
            surfshark_privkey=privkey,
            delay=0.5,
            save_callback=lambda: save_nodes_file(all_nodes)
        )
    )

    return {
        "success": True,
        "started": len(to_start),
        "message": f"Memulai {len(to_start)} harvester secara bertahap."
    }


@app.post("/api/harvester/stop-all")
async def stop_harvester_all():
    all_nodes = get_combined_nodes()
    stopped = supervisor.stop_all_harvesters(all_nodes)
    save_nodes_file(all_nodes)
    return {"success": True, "stopped": stopped, "message": f"{stopped} harvester telah dihentikan."}


@app.post("/api/harvester/start-surfshark")
async def start_harvester_surfshark():
    token = config.get("traff_token", "")
    privkey = config.get("surfshark_private_key", "")
    if not token:
        raise HTTPException(status_code=400, detail="Token TraffMonetizer belum diisi.")
    if not privkey:
        raise HTTPException(status_code=400, detail="WireGuard Private Key Surfshark belum diisi.")
    if not surfshark_nodes:
        raise HTTPException(status_code=400, detail="Belum ada node Surfshark yang di-generate.")

    to_start = [n for n in surfshark_nodes if n.status != "RUNNING"]
    for n in to_start:
        n.status = "STARTING"
    save_nodes_file(get_combined_nodes())

    asyncio.create_task(
        supervisor.start_harvesters_staggered(
            to_start,
            token,
            surfshark_privkey=privkey,
            delay=0.5,
            save_callback=lambda: save_nodes_file(get_combined_nodes())
        )
    )
    return {"success": True, "started": len(to_start), "message": f"Memulai {len(to_start)} harvester Surfshark."}


@app.post("/api/harvester/stop-surfshark")
async def stop_harvester_surfshark():
    stopped = supervisor.stop_filtered_harvesters(surfshark_nodes, "surfshark")
    save_nodes_file(get_combined_nodes())
    return {"success": True, "stopped": stopped, "message": f"{stopped} harvester Surfshark dihentikan."}


@app.post("/api/harvester/start-proxies")
async def start_harvester_proxies():
    token = config.get("traff_token", "")
    if not token:
        raise HTTPException(status_code=400, detail="Token TraffMonetizer belum diisi.")
    if not custom_proxy_nodes:
        raise HTTPException(status_code=400, detail="Belum ada custom proxy yang disimpan.")

    to_start = [n for n in custom_proxy_nodes if n.status != "RUNNING"]
    for n in to_start:
        n.status = "STARTING"
    save_nodes_file(get_combined_nodes())

    asyncio.create_task(
        supervisor.start_harvesters_staggered(
            to_start,
            token,
            delay=0.5,
            save_callback=lambda: save_nodes_file(get_combined_nodes())
        )
    )
    return {"success": True, "started": len(to_start), "message": f"Memulai {len(to_start)} harvester proxy."}


@app.post("/api/harvester/stop-proxies")
async def stop_harvester_proxies():
    stopped = supervisor.stop_filtered_harvesters(custom_proxy_nodes, "proxy")
    save_nodes_file(get_combined_nodes())
    return {"success": True, "stopped": stopped, "message": f"{stopped} harvester custom proxy dihentikan."}


# Relay gateway controls
@app.post("/api/relay/start-all")
async def start_relay_all():
    all_nodes = get_combined_nodes()
    if not all_nodes:
        raise HTTPException(status_code=400, detail="Belum ada node untuk membuka port relay.")

    # WireProxy tunnels must run for Surfshark nodes to accept local SOCKS5 connections
    privkey = config.get("surfshark_private_key", "")
    token = config.get("traff_token", "TM_TOKEN")
    for n in surfshark_nodes:
        if not n.wp_pid:
            supervisor.start_harvester(n, token, surfshark_privkey=privkey)

    started = await relay_manager.sync_all_relays(all_nodes)
    save_nodes_file(all_nodes)
    return {
        "success": True,
        "ports_opened": started,
        "message": f"Berhasil membuka {started} port relay proxy (Port {relay_manager.start_port} s/d {relay_manager.start_port + started - 1})."
    }


@app.post("/api/relay/stop-all")
async def stop_relay_all():
    await relay_manager.stop_all()
    all_nodes = get_combined_nodes()
    for n in all_nodes:
        n.relay_status = "STOPPED"
    save_nodes_file(all_nodes)
    return {"success": True, "message": "Seluruh port relay proxy telah ditutup."}


# Hybrid dual controls (Starts Harvester + Relay simultaneously)
@app.post("/api/hybrid/start-all")
async def start_hybrid_all():
    token = config.get("traff_token", "")
    privkey = config.get("surfshark_private_key", "")
    if not token:
        raise HTTPException(status_code=400, detail="Token TraffMonetizer belum diisi.")
    all_nodes = get_combined_nodes()
    if not all_nodes:
        raise HTTPException(status_code=400, detail="Belum ada node yang siap dijalankan.")

    # 1. Start all harvesters (skip dead/error nodes)
    to_start = [n for n in all_nodes if n.status != "RUNNING" and (n.is_alive is not False and n.status != "ERROR")]
    for n in to_start:
        n.status = "STARTING"
    save_nodes_file(all_nodes)

    asyncio.create_task(
        supervisor.start_harvesters_staggered(
            to_start,
            token,
            surfshark_privkey=privkey,
            delay=0.5,
            save_callback=lambda: save_nodes_file(all_nodes)
        )
    )

    # 2. Start all relay ports
    relay_ports_started = await relay_manager.sync_all_relays(all_nodes)
    save_nodes_file(all_nodes)

    return {
        "success": True,
        "harvesters": len(to_start),
        "relay_ports": relay_ports_started,
        "message": f"Mode Hybrid Aktif: {len(to_start)} Harvester Monetisasi + {relay_ports_started} Port Relay Gateway."
    }


@app.post("/api/hybrid/stop-all")
async def stop_hybrid_all():
    all_nodes = get_combined_nodes()
    stopped_h = supervisor.stop_all_harvesters(all_nodes)
    await relay_manager.stop_all()
    for n in all_nodes:
        n.relay_status = "STOPPED"
    save_nodes_file(all_nodes)
    return {"success": True, "message": f"Seluruh worker ({stopped_h} Harvester & semua Port Relay) telah dihentikan."}


# Single node controls
@app.post("/api/node/{node_id}/start-harvester")
async def start_single_harvester(node_id: int):
    token = config.get("traff_token", "")
    privkey = config.get("surfshark_private_key", "")
    node = find_node_by_id(node_id)
    if not node:
        raise HTTPException(status_code=404, detail="Node tidak ditemukan.")
    ok = supervisor.start_harvester(node, token, surfshark_privkey=privkey)
    if not ok:
        raise HTTPException(status_code=500, detail=node.error or "Gagal menjalankan harvester.")
    save_nodes_file(get_combined_nodes())
    return {"success": True, "node": node.to_dict()}


@app.post("/api/node/{node_id}/stop-harvester")
async def stop_single_harvester(node_id: int):
    node = find_node_by_id(node_id)
    if not node:
        raise HTTPException(status_code=404, detail="Node tidak ditemukan.")
    supervisor.stop_harvester(node)
    save_nodes_file(get_combined_nodes())
    return {"success": True, "node": node.to_dict()}


@app.post("/api/node/{node_id}/start-relay")
async def start_single_relay(node_id: int):
    node = find_node_by_id(node_id)
    if not node:
        raise HTTPException(status_code=404, detail="Node tidak ditemukan.")
    all_nodes = get_combined_nodes()
    idx = all_nodes.index(node)
    port = config.get("relay_start_port", 10001) + idx

    if getattr(node, "node_type", "proxy") == "surfshark" and not node.wp_pid:
        privkey = config.get("surfshark_private_key", "")
        token = config.get("traff_token", "TM_TOKEN")
        supervisor.start_harvester(node, token, surfshark_privkey=privkey)

    ok = await relay_manager.start_relay_for_node(node, port)
    if not ok:
        raise HTTPException(status_code=500, detail="Gagal membuka port relay.")
    save_nodes_file(all_nodes)
    return {"success": True, "port": port, "node": node.to_dict()}


@app.post("/api/node/{node_id}/stop-relay")
async def stop_single_relay(node_id: int):
    node = find_node_by_id(node_id)
    if not node:
        raise HTTPException(status_code=404, detail="Node tidak ditemukan.")
    await relay_manager.stop_relay_for_node(node)
    save_nodes_file(get_combined_nodes())
    return {"success": True, "node": node.to_dict()}


@app.get("/api/node/{node_id}/logs")
async def get_node_logs(node_id: int):
    node = find_node_by_id(node_id)
    if not node:
        return PlainTextResponse("Node tidak ditemukan.", status_code=404)
    logs = supervisor.get_node_logs(node)
    return PlainTextResponse(logs)


@app.delete("/api/node/{node_id}")
async def delete_single_node(node_id: int):
    global surfshark_nodes, custom_proxy_nodes
    node = find_node_by_id(node_id)
    if not node:
        raise HTTPException(status_code=404, detail="Node tidak ditemukan.")
    supervisor.stop_harvester(node)
    await relay_manager.stop_relay_for_node(node)
    surfshark_nodes = [n for n in surfshark_nodes if n.id != node_id]
    custom_proxy_nodes = [n for n in custom_proxy_nodes if n.id != node_id]

    remaining_proxy_raw = "\n".join(n.raw for n in custom_proxy_nodes if n.raw)
    save_proxies_file(remaining_proxy_raw)
    save_nodes_file(get_combined_nodes())
    return {"success": True, "message": f"Node #{node_id} berhasil dihapus."}


@app.delete("/api/nodes/error")
async def clear_error_nodes():
    global surfshark_nodes, custom_proxy_nodes
    all_nodes = get_combined_nodes()
    dead_nodes = [n for n in all_nodes if n.status == "ERROR" or n.is_alive is False]
    for n in dead_nodes:
        supervisor.stop_harvester(n)
        await relay_manager.stop_relay_for_node(n)

    dead_ids = set(n.id for n in dead_nodes)
    surfshark_nodes = [n for n in surfshark_nodes if n.id not in dead_ids]
    custom_proxy_nodes = [n for n in custom_proxy_nodes if n.id not in dead_ids]

    remaining_proxy_raw = "\n".join(n.raw for n in custom_proxy_nodes if n.raw)
    save_proxies_file(remaining_proxy_raw)
    save_nodes_file(get_combined_nodes())

    return {
        "success": True,
        "cleared": len(dead_ids),
        "message": f"Berhasil membuang {len(dead_ids)} node yang error atau offline."
    }


@app.delete("/api/nodes/surfshark")
async def clear_surfshark_pool():
    global surfshark_nodes
    supervisor.stop_filtered_harvesters(surfshark_nodes, "surfshark")
    for n in surfshark_nodes:
        await relay_manager.stop_relay_for_node(n)
    count = len(surfshark_nodes)
    surfshark_nodes = []
    save_nodes_file(get_combined_nodes())
    return {"success": True, "cleared": count, "message": f"{count} node Surfshark berhasil dihapus."}


@app.delete("/api/nodes/proxies")
async def clear_proxy_pool():
    global custom_proxy_nodes
    supervisor.stop_filtered_harvesters(custom_proxy_nodes, "proxy")
    for n in custom_proxy_nodes:
        await relay_manager.stop_relay_for_node(n)
    count = len(custom_proxy_nodes)
    custom_proxy_nodes = []
    save_proxies_file("")
    save_nodes_file(get_combined_nodes())
    return {"success": True, "cleared": count, "message": f"{count} custom proxy berhasil dihapus."}


# Exports
@app.get("/api/export/relay-client")
async def export_relay_client():
    server_ip = get_server_ip()
    u = config.get("relay_client_user", "gemini")
    p = config.get("relay_client_pass", "gemini")
    all_nodes = get_combined_nodes()

    lines = []
    for i, node in enumerate(all_nodes):
        port = config.get("relay_start_port", 10001) + i
        c = node.country if node.country and node.country != "Unknown" else "Node"
        label = f"# {node.device_name or f'Node-{node.id}'} ({c})"
        lines.append(label)
        lines.append(f"{server_ip}:{port}:{u}:{p}")

    content = "\n".join(lines)
    return PlainTextResponse(
        content,
        headers={"Content-Disposition": f"attachment; filename=traffnode_v3_relay_client_{int(time.time())}.txt"}
    )


@app.get("/api/export/live-proxies")
async def export_live_proxies(alive_only: bool = True):
    all_proxies = custom_proxy_nodes
    if alive_only:
        targets = [n for n in all_proxies if n.is_alive is not False and n.status != "ERROR"]
    else:
        targets = all_proxies

    lines = []
    for n in targets:
        if n.user and n.password:
            lines.append(f"{n.host}:{n.port}:{n.user}:{n.password}")
        elif n.host and n.port:
            lines.append(f"{n.host}:{n.port}")
        elif n.raw:
            lines.append(n.raw)

    content = "\n".join(lines)
    return PlainTextResponse(
        content,
        headers={"Content-Disposition": f"attachment; filename=live_upstream_proxies_{int(time.time())}.txt"}
    )


@app.get("/api/export/live-config")
async def export_live_config():
    all_nodes = get_combined_nodes()
    data = [n.to_dict(include_password=True) for n in all_nodes]
    content = json.dumps(data, indent=2)
    return PlainTextResponse(
        content,
        headers={
            "Content-Type": "application/json",
            "Content-Disposition": f"attachment; filename=traffnode_v3_config_{int(time.time())}.json"
        }
    )


if __name__ == "__main__":
    import sys
    if len(sys.argv) >= 2 and sys.argv[1] in ("set-password", "--set-password", "passwd"):
        if len(sys.argv) < 4:
            print("Penggunaan: python3 app.py set-password <username> <new_password>")
            sys.exit(1)
        new_u = sys.argv[2].strip()
        new_p = sys.argv[3].strip()
        cfg = load_config()
        cfg["dashboard_username"] = new_u
        cfg["dashboard_password"] = new_p
        save_config(cfg)
        print(f"✅ Kredensial TraffNode V3 berhasil diubah!")
        print(f"Username : {new_u}")
        print(f"Password : {new_p}")
        sys.exit(0)

    import uvicorn
    cfg = load_config()
    port = cfg.get("dashboard_port", 80)
    print(f"TraffNode V3 Cockpit starting on http://{cfg.get('host', '0.0.0.0')}:{port}")
    uvicorn.run("app:app", host=cfg.get("host", "0.0.0.0"), port=port, reload=False)
