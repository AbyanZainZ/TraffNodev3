import asyncio
import base64
import socket
import struct
import time
from typing import Optional, Dict, Any, Tuple, List
from checker import ProxyNode

BUFFER_SIZE = 65536

class ProxyRelayPort:
    def __init__(
        self,
        port: int,
        upstream: ProxyNode,
        client_user: str = "gemini",
        client_pass: str = "gemini",
        bind_host: str = "0.0.0.0"
    ):
        self.port = port
        self.upstream = upstream
        self.client_user = client_user
        self.client_pass = client_pass
        self.bind_host = bind_host

        self.server: Optional[asyncio.Server] = None
        self.is_running = False
        self.active_conns = 0
        self.total_conns = 0
        self.bytes_in = 0
        self.bytes_out = 0
        self.error: Optional[str] = None
        self.start_time = 0.0

    async def start(self):
        try:
            self.server = await asyncio.start_server(
                self.handle_client,
                self.bind_host,
                self.port
            )
            self.is_running = True
            self.start_time = time.time()
            self.error = None
            self.upstream.relay_status = "RUNNING"
            self.upstream.relay_port = self.port
        except Exception as e:
            self.is_running = False
            self.error = str(e)
            self.upstream.relay_status = "ERROR"
            raise e

    async def stop(self):
        self.is_running = False
        if self.server:
            self.server.close()
            try:
                await self.server.wait_closed()
            except Exception:
                pass
            self.server = None
        self.upstream.relay_status = "STOPPED"

    def get_stats(self) -> Dict[str, Any]:
        return {
            "node_id": self.upstream.id,
            "port": self.port,
            "is_running": self.is_running,
            "active_conns": self.active_conns,
            "total_conns": self.total_conns,
            "bytes_in": self.bytes_in,
            "bytes_out": self.bytes_out,
            "uptime_sec": int(time.time() - self.start_time) if self.is_running else 0,
            "error": self.error,
            "upstream": self.upstream.to_dict()
        }

    async def handle_client(self, client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter):
        self.active_conns += 1
        self.total_conns += 1
        try:
            # Peek first byte to auto-detect protocol without consuming buffer
            first_byte = await client_reader.read(1)
            if not first_byte:
                return

            if first_byte == b'\x05':
                await self._handle_socks5(first_byte, client_reader, client_writer)
            else:
                await self._handle_http(first_byte, client_reader, client_writer)
        except Exception:
            pass
        finally:
            self.active_conns = max(0, self.active_conns - 1)
            try:
                client_writer.close()
                await client_writer.wait_closed()
            except Exception:
                pass

    async def _handle_http(self, first_byte: bytes, client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter):
        header_bytes = first_byte + await client_reader.readuntil(b'\r\n\r\n')
        header_text = header_bytes.decode('latin1', errors='ignore')
        lines = header_text.split('\r\n')
        req_line = lines[0] if lines else ""

        auth_ok = False
        if not self.client_user and not self.client_pass:
            auth_ok = True
        else:
            for l in lines[1:]:
                if l.lower().startswith('proxy-authorization: basic '):
                    cred_b64 = l.split(' ', 2)[2].strip()
                    try:
                        decoded = base64.b64decode(cred_b64).decode('utf-8', errors='ignore')
                        u, p = decoded.split(':', 1)
                        if u == self.client_user and p == self.client_pass:
                            auth_ok = True
                    except Exception:
                        pass
                    break

        if not auth_ok:
            resp = (
                "HTTP/1.1 407 Proxy Authentication Required\r\n"
                "Proxy-Authenticate: Basic realm=\"TraffNode V3 Gateway\"\r\n"
                "Content-Length: 0\r\n"
                "Connection: close\r\n\r\n"
            )
            client_writer.write(resp.encode('ascii'))
            await client_writer.drain()
            return

        parts = req_line.split()
        if len(parts) < 2:
            return
        method, target = parts[0].upper(), parts[1]

        target_host = ""
        target_port = 80

        if method == "CONNECT":
            if ":" in target:
                target_host, p_str = target.split(":", 1)
                target_port = int(p_str)
            else:
                target_host = target
                target_port = 443
        else:
            m_url = target.replace("http://", "").replace("https://", "")
            host_part = m_url.split("/", 1)[0]
            if ":" in host_part:
                target_host, p_str = host_part.split(":", 1)
                target_port = int(p_str)
            else:
                target_host = host_part
                target_port = 80

        if not target_host:
            return

        up_reader, up_writer = await self._connect_upstream(target_host, target_port)
        if not up_reader or not up_writer:
            client_writer.write(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n")
            await client_writer.drain()
            return

        if method == "CONNECT":
            client_writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            await client_writer.drain()
        else:
            # Reconstruct clean request line for plain HTTP forwarding
            clean_path = target
            if target.startswith("http://") or target.startswith("https://"):
                clean_path = "/" + target.split("/", 3)[-1] if len(target.split("/", 3)) > 3 else "/"
            filtered_headers = [f"{parts[0]} {clean_path} {parts[2]}"]
            for l in lines[1:]:
                if not l.lower().startswith('proxy-authorization:') and not l.lower().startswith('proxy-connection:'):
                    filtered_headers.append(l)
            filtered_headers.append("Connection: close")
            fwd_payload = "\r\n".join(filtered_headers) + "\r\n\r\n"
            up_writer.write(fwd_payload.encode('latin1'))
            await up_writer.drain()

        await self._pipe_bidirectional(client_reader, client_writer, up_reader, up_writer)

    async def _handle_socks5(self, first_byte: bytes, client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter):
        nmethods_b = await client_reader.read(1)
        if not nmethods_b:
            return
        nmethods = nmethods_b[0]
        methods = await client_reader.read(nmethods)

        if self.client_user or self.client_pass:
            if b'\x02' not in methods:
                client_writer.write(b'\x05\xFF')
                await client_writer.drain()
                return

            client_writer.write(b'\x05\x02')
            await client_writer.drain()

            sub_ver = await client_reader.read(1)
            if sub_ver != b'\x01':
                return
            ulen = (await client_reader.read(1))[0]
            uname = (await client_reader.read(ulen)).decode('utf-8', errors='ignore')
            plen = (await client_reader.read(1))[0]
            passwd = (await client_reader.read(plen)).decode('utf-8', errors='ignore')

            if uname == self.client_user and passwd == self.client_pass:
                client_writer.write(b'\x01\x00')
                await client_writer.drain()
            else:
                client_writer.write(b'\x01\x01')
                await client_writer.drain()
                return
        else:
            client_writer.write(b'\x05\x00')
            await client_writer.drain()

        req_header = await client_reader.read(4)
        if len(req_header) < 4 or req_header[0] != 5 or req_header[1] != 1:
            client_writer.write(b'\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00')
            await client_writer.drain()
            return

        atyp = req_header[3]
        target_host = ""
        if atyp == 1:
            ip_b = await client_reader.read(4)
            target_host = socket.inet_ntoa(ip_b)
        elif atyp == 3:
            dlen = (await client_reader.read(1))[0]
            target_host = (await client_reader.read(dlen)).decode('utf-8', errors='ignore')
        elif atyp == 4:
            ip_b = await client_reader.read(16)
            target_host = socket.inet_ntop(socket.AF_INET6, ip_b)
        else:
            return

        port_b = await client_reader.read(2)
        target_port = struct.unpack("!H", port_b)[0]

        up_reader, up_writer = await self._connect_upstream(target_host, target_port)
        if not up_reader or not up_writer:
            client_writer.write(b'\x05\x04\x00\x01\x00\x00\x00\x00\x00\x00')
            await client_writer.drain()
            return

        client_writer.write(b'\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00')
        await client_writer.drain()

        await self._pipe_bidirectional(client_reader, client_writer, up_reader, up_writer)

    async def _connect_upstream(self, target_host: str, target_port: int) -> Tuple[Optional[asyncio.StreamReader], Optional[asyncio.StreamWriter]]:
        up = self.upstream
        # Resolve target endpoint depending on whether node is Surfshark WireProxy or Custom Proxy
        if getattr(up, "node_type", "proxy") == "surfshark":
            target_up_host = "127.0.0.1"
            target_up_port = up.port or (21000 + up.id)
            up_proto = "SOCKS5"
            up_user = None
            up_pass = None
        else:
            target_up_host = up.host
            target_up_port = up.port
            up_proto = (up.protocol or "HTTP").upper()
            up_user = up.user
            up_pass = up.password

        try:
            up_reader, up_writer = await asyncio.wait_for(
                asyncio.open_connection(target_up_host, target_up_port),
                timeout=8.0
            )

            if "SOCKS5" in up_proto:
                if up_user and up_pass:
                    up_writer.write(b'\x05\x02\x00\x02')
                    await up_writer.drain()
                    resp = await asyncio.wait_for(up_reader.read(2), timeout=5.0)
                    if resp[1] == 2:
                        u_b = up_user.encode('utf-8')
                        p_b = up_pass.encode('utf-8')
                        up_writer.write(b'\x01' + bytes([len(u_b)]) + u_b + bytes([len(p_b)]) + p_b)
                        await up_writer.drain()
                        auth_resp = await asyncio.wait_for(up_reader.read(2), timeout=5.0)
                        if auth_resp[1] != 0:
                            up_writer.close()
                            return None, None
                else:
                    up_writer.write(b'\x05\x01\x00')
                    await up_writer.drain()
                    resp = await asyncio.wait_for(up_reader.read(2), timeout=5.0)
                    if resp[1] != 0:
                        up_writer.close()
                        return None, None

                host_b = target_host.encode('utf-8')
                port_b = struct.pack("!H", target_port)
                req = b'\x05\x01\x00\x03' + bytes([len(host_b)]) + host_b + port_b
                up_writer.write(req)
                await up_writer.drain()

                conn_resp = await asyncio.wait_for(up_reader.read(4), timeout=8.0)
                if conn_resp[1] != 0:
                    up_writer.close()
                    return None, None

                atyp = conn_resp[3]
                if atyp == 1:
                    await up_reader.read(4 + 2)
                elif atyp == 3:
                    d_len = (await up_reader.read(1))[0]
                    await up_reader.read(d_len + 2)
                elif atyp == 4:
                    await up_reader.read(16 + 2)

                return up_reader, up_writer

            else:
                conn_line = f"CONNECT {target_host}:{target_port} HTTP/1.1\r\nHost: {target_host}:{target_port}\r\n"
                if up_user and up_pass:
                    cred = base64.b64encode(f"{up_user}:{up_pass}".encode('utf-8')).decode('ascii')
                    conn_line += f"Proxy-Authorization: Basic {cred}\r\n"
                conn_line += "Proxy-Connection: Keep-Alive\r\n\r\n"

                up_writer.write(conn_line.encode('ascii'))
                await up_writer.drain()

                resp_data = await asyncio.wait_for(up_reader.readuntil(b'\r\n\r\n'), timeout=8.0)
                first_resp_line = resp_data.split(b'\r\n', 1)[0].decode('ascii', errors='ignore')
                if " 200 " not in first_resp_line:
                    up_writer.close()
                    return None, None

                return up_reader, up_writer

        except Exception:
            return None, None

    async def _pipe_bidirectional(self, c_reader, c_writer, u_reader, u_writer):
        async def forward(src_r, dst_w, is_inbound=True):
            try:
                while True:
                    data = await src_r.read(BUFFER_SIZE)
                    if not data:
                        break
                    dst_w.write(data)
                    await dst_w.drain()
                    if is_inbound:
                        self.bytes_in += len(data)
                    else:
                        self.bytes_out += len(data)
            except Exception:
                pass
            finally:
                try:
                    dst_w.close()
                except Exception:
                    pass

        await asyncio.gather(
            forward(c_reader, u_writer, is_inbound=True),
            forward(u_reader, c_writer, is_inbound=False),
            return_exceptions=True
        )


class RelayManager:
    def __init__(
        self,
        start_port: int = 10001,
        client_user: str = "gemini",
        client_pass: str = "gemini",
        bind_host: str = "0.0.0.0"
    ):
        self.start_port = start_port
        self.client_user = client_user
        self.client_pass = client_pass
        self.bind_host = bind_host
        self.ports: Dict[int, ProxyRelayPort] = {}
        self._lock = asyncio.Lock()

    async def start_relay_for_node(self, node: ProxyNode, port: int) -> bool:
        async with self._lock:
            if port in self.ports:
                await self.ports[port].stop()
                del self.ports[port]

            relay = ProxyRelayPort(
                port=port,
                upstream=node,
                client_user=self.client_user,
                client_pass=self.client_pass,
                bind_host=self.bind_host
            )
            try:
                await relay.start()
                self.ports[port] = relay
                return True
            except Exception as e:
                relay.error = str(e)
                self.ports[port] = relay
                return False

    async def stop_relay_for_node(self, node: ProxyNode):
        async with self._lock:
            port_to_remove = None
            for p, relay in self.ports.items():
                if relay.upstream.id == node.id:
                    await relay.stop()
                    port_to_remove = p
                    break
            if port_to_remove:
                del self.ports[port_to_remove]

    async def sync_all_relays(self, nodes: List[ProxyNode]) -> int:
        async with self._lock:
            await self._stop_all_unlocked()
            started_count = 0
            for i, node in enumerate(nodes):
                port_num = self.start_port + i
                relay = ProxyRelayPort(
                    port=port_num,
                    upstream=node,
                    client_user=self.client_user,
                    client_pass=self.client_pass,
                    bind_host=self.bind_host
                )
                try:
                    await relay.start()
                    self.ports[port_num] = relay
                    started_count += 1
                except Exception as e:
                    relay.error = str(e)
                    self.ports[port_num] = relay

                # Brief pacing prevents kernel epoll socket allocation spikes
                await asyncio.sleep(0.02)

            return started_count

    async def _stop_all_unlocked(self):
        for port, relay in list(self.ports.items()):
            await relay.stop()
        self.ports.clear()

    async def stop_all(self):
        async with self._lock:
            await self._stop_all_unlocked()

    def get_all_stats(self) -> List[Dict[str, Any]]:
        return [r.get_stats() for r in sorted(self.ports.values(), key=lambda x: x.port)]

    def get_relay_for_node(self, node_id: int) -> Optional[ProxyRelayPort]:
        for r in self.ports.values():
            if r.upstream.id == node_id:
                return r
        return None
