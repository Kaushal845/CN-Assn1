import socket
import struct
import threading
import json
import sys
from datetime import datetime
from scapy.all import DNS
from typing import Tuple

IP_POOL = [
 "192.168.1.1","192.168.1.2","192.168.1.3","192.168.1.4","192.168.1.5",
 "192.168.1.6","192.168.1.7","192.168.1.8","192.168.1.9","192.168.1.10",
 "192.168.1.11","192.168.1.12","192.168.1.13","192.168.1.14","192.168.1.15"
]

# Each window has time_range, hash_mod and ip_pool_start
TIMESTAMP_RULES = {
    "morning":   {"time_range": "04:00-11:59", "hash_mod": 5, "ip_pool_start": 0,  "description": "Morning traffic routed to first 5 IPs"},
    "afternoon": {"time_range": "12:00-19:59", "hash_mod": 5, "ip_pool_start": 5,  "description": "Afternoon traffic routed to middle 5 IPs"},
    "night":     {"time_range": "20:00-03:59", "hash_mod": 5, "ip_pool_start": 10, "description": "Night traffic routed to last 5 IPs"}
}

# Framing helpers
def recv_exact(conn: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("socket closed")
        buf.extend(chunk)
    return bytes(buf)

def recv_frame(conn: socket.socket) -> bytes:
    header = recv_exact(conn, 2)
    (length,) = struct.unpack("!H", header)
    payload = recv_exact(conn, length)
    return payload

def send_frame(conn: socket.socket, payload: bytes) -> None:
    if len(payload) > 0xFFFF:
        raise ValueError("frame too large")
    conn.sendall(struct.pack("!H", len(payload)) + payload)

# Rule application
def get_time_window(hour: int) -> Tuple[str, dict]:
    # morning: 04..11
    if 4 <= hour <= 11:
        return "morning", TIMESTAMP_RULES["morning"]
    # afternoon: 12..19
    if 12 <= hour <= 19:
        return "afternoon", TIMESTAMP_RULES["afternoon"]
    # night: 20..23 or 0..3
    return "night", TIMESTAMP_RULES["night"]

def pick_ip_from_header(header: str) -> str:
    try:
        hh = int(header[0:2])
    except Exception:
        hh = 0
    try:
        id_val = int(header[6:8])
    except Exception:
        id_val = 0
    _, rule = get_time_window(hh)
    mod = rule.get("hash_mod", 5)
    start = rule.get("ip_pool_start", 0)
    idx = start + (id_val % mod)
    # clamp
    idx = idx % len(IP_POOL)
    return IP_POOL[idx]

# Client handler
def handle_client(conn: socket.socket, addr) -> None:
    print(f"[{datetime.now()}] Connection from {addr}")
    try:
        while True:
            try:
                frame = recv_frame(conn)
            except ConnectionError:
                break
            if len(frame) < 8:
                print("Frame too small")
                print("Connection closed")
                break
            header = frame[:8].decode("ascii", errors="ignore")
            dns_bytes = frame[8:]
            qname = None
            try:
                dns = DNS(dns_bytes)
                if dns.qdcount > 0 and dns.qd is not None:
                    # extract qname
                    q = dns.qd
                    if hasattr(q, "qname"):
                        if isinstance(q.qname, bytes):
                            qname = q.qname.decode(errors="ignore")
                        else:
                            qname = str(q.qname)
            except Exception as e:
                # proceed with IP selection based on header
                qname = None

            resolved_ip = pick_ip_from_header(header)
            resp_obj = {"id": header, "qname": qname or "", "resolved": resolved_ip}
            resp_bytes = header.encode("ascii") + json.dumps(resp_obj).encode("utf-8")
            send_frame(conn, resp_bytes)

            # server-console log
            print(f"[{header}] qname={qname or '<no-qname>'} -> {resolved_ip}")
    finally:
        conn.close()
        print(f"[{datetime.now()}] Disconnected {addr}")

# Server runner
def run_server(bind_host: str = "0.0.0.0", bind_port: int = 53530):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((bind_host, bind_port))
        s.listen(8)
        print(f"[*] Server listening on {bind_host}:{bind_port}")
        while True:
            conn, addr = s.accept()
            t = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
            t.start()

if __name__ == "__main__":
    host = sys.argv[1] if len(sys.argv) >= 2 else "0.0.0.0"
    port = int(sys.argv[2]) if len(sys.argv) >= 3 else 53530
    run_server(host, port)
