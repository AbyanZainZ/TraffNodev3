import time
import psutil
from typing import Dict, Tuple

class BandwidthTracker:
    def __init__(self):
        self._last_net_io = psutil.net_io_counters()
        self._last_poll_time = time.time()
        self._proc_cache: Dict[int, Tuple[int, int]] = {}

    def get_system_bandwidth(self) -> Dict[str, float]:
        now = time.time()
        curr_net_io = psutil.net_io_counters()
        dt = max(0.1, now - self._last_poll_time)

        bytes_sent_delta = curr_net_io.bytes_sent - self._last_net_io.bytes_sent
        bytes_recv_delta = curr_net_io.bytes_recv - self._last_net_io.bytes_recv

        self._last_net_io = curr_net_io
        self._last_poll_time = now

        return {
            "total_sent_bytes": curr_net_io.bytes_sent,
            "total_recv_bytes": curr_net_io.bytes_recv,
            "speed_up_bps": round(bytes_sent_delta / dt),
            "speed_down_bps": round(bytes_recv_delta / dt)
        }

    def update_proc_traffic(self, pid: int, node) -> Tuple[int, int]:
        try:
            if not psutil.pid_exists(pid):
                return node.bytes_in, node.bytes_out
            p = psutil.Process(pid)
            if hasattr(p, "io_counters"):
                io = p.io_counters()
                node.bytes_in = getattr(io, "read_bytes", 0)
                node.bytes_out = getattr(io, "write_bytes", 0)
        except Exception:
            pass
        return node.bytes_in, node.bytes_out

def format_bytes(bytes_num: int) -> str:
    if not bytes_num or bytes_num <= 0:
        return "0 B"
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_num < 1024.0:
            return f"{bytes_num:.2f} {unit}"
        bytes_num /= 1024.0
    return f"{bytes_num:.2f} PB"
