# ⚡ TraffNode V3 Cockpit

> **All-in-One Hybrid Passive Income Harvester & Inbound Authenticated Proxy Gateway**

TraffNode V3 menggabungkan kemampuan **TraffNode V2** (Passive Income Harvester berbasis 925 IP fisik Surfshark WireGuard + Custom Proxy) dengan **ProxyChain** (Multi-Port Inbound Authenticated Relay Gateway).

$$\text{Client / Bot} \xrightarrow{\text{Auth: gemini:gemini}} \mathbf{IP\_VPS:10001..N} \xrightarrow{\text{Relay}} \mathbf{Surfshark / Custom Proxy} \xrightarrow{\text{Exit IP}} \text{Target Web}$$

Secara simultan di latar belakang:
$$\text{TraffMonetizer Client} \xrightarrow{\text{Bandwidth Sharing}} \mathbf{Surfshark / Custom Proxy} \longrightarrow \text{Dollar Passive Income}$$

---

## ✨ Fitur Utama V3

1. **🚀 Dual-Engine Hybrid Concurrency**:
   - Menjalankan monetisasi TraffMonetizer dan membuka port relay proxy sekaligus pada satu VPS tanpa konflik.
   - Setiap pool (Harvester / Relay) dapat di-start atau di-stop secara independen.
2. **🦈 925 IP Fisik Surfshark WireGuard**:
   - Mendukung routing langsung 925 server fisik global tanpa duplicate IP penalty.
   - IP Surfshark dapat di-relay sebagai proxy port (`IP_VPS:10001..N`) untuk bot/browser Anda.
3. **🌐 Custom Residential / Datacenter Proxy Pool**:
   - Menyimpan dan mengetes ratusan proxy custom (HTTP/SOCKS5/SOCKS4).
4. **🔒 Inbound Client Authentication**:
   - Seluruh port relay dilindungi oleh otentikasi kustom (default: `gemini:gemini`, dapat diubah di dashboard).
   - Mendukung HTTP Basic Auth dan SOCKS5 RFC 1929 secara auto-sensing.
5. **🛡️ Kernel Limit & Process Shield**:
   - `TasksMax=infinity`, `kernel.pid_max=4194304`, dan Low-Memory GC mencegah error `[Errno 11]`.
6. **📋 One-Click Export**:
   - Export Relay Client list (`IP_VPS:PORT:USER:PASS`) siap pakai untuk bot.
   - Export Live Upstream Proxies (`live_proxies.txt`).
   - Export Full Config (`config.json`).

---

## 💻 Menjalankan di Localhost (Windows)

Klik ganda file:
```cmd
run_localhost.bat
```
Buka browser Anda di: `http://127.0.0.1:8888`

---

## ☁️ Deploy ke VPS Linux (Ubuntu / Debian)

Jalankan perintah berikut di terminal SSH VPS Anda:
```bash
sudo bash deploy_vps.sh
```
Akses dashboard di: `http://IP_VPS:8888`
Port relay client: `http://IP_VPS:10001 s/d 11000` (Auth: `gemini:gemini`)
