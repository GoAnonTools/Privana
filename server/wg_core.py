# server/wg_core.py
from __future__ import annotations
import os, sqlite3, subprocess, ipaddress, json
from pathlib import Path
from datetime import datetime

# --- env / defaults ---
WG_IFACE   = os.getenv("WG_INTERFACE", "wg0")
WG_HOST    = os.getenv("WG_HOST", "127.0.0.1")
WG_PORT    = int(os.getenv("WG_PORT", "51820"))
WG_CIDR    = os.getenv("WG_CIDR", "10.7.0.0/24")
WG_DNS     = os.getenv("WG_DNS", "1.1.1.1")
WG_ALLOWED = os.getenv("WG_ALLOWED_IPS", "0.0.0.0/0,::/0")

ROOT_DIR = Path(__file__).resolve().parents[1]   # project root (…/server -> …/)
DB_PATH  = str(ROOT_DIR / "privana.db")

def _db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def _run(cmd: list[str], timeout=10):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
        return p.returncode, (p.stdout or "").strip(), (p.stderr or "").strip()
    except Exception as e:
        return 1, "", str(e)

def _wg(cmd_args: list[str], timeout=10):
    return _run(["wg", *cmd_args], timeout=timeout)

def _gen_keypair():
    code, priv, err = _wg(["genkey"])
    if code != 0: return None, None, f"wg genkey failed: {err}"
    code, pub, err2 = _run(["bash","-lc", f"printf %s \"{priv}\" | wg pubkey"])
    if code != 0: return None, None, f"wg pubkey failed: {err2}"
    return priv.strip(), pub.strip(), None

def _server_public_key():
    # Try /etc/wireguard/<iface>.pub, then /etc/wireguard/server_public.key
    cand = [
        f"/etc/wireguard/{WG_IFACE}.pub",
        "/etc/wireguard/server_public.key",
    ]
    for p in cand:
        try:
            if os.path.exists(p):
                return open(p,"r",encoding="utf-8").read().strip()
        except Exception:
            pass
    # fallback: wg show
    code, out, err = _wg(["show", WG_IFACE, "public-key"])
    return out.strip() if code==0 and out.strip() else None

def _ensure_tables(conn: sqlite3.Connection):
    conn.execute("""
      CREATE TABLE IF NOT EXISTS peer_allocations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        device_id INTEGER NOT NULL,
        user_id   INTEGER NOT NULL,
        public_key TEXT NOT NULL,
        ip_addr   TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE (device_id)
      )
    """)
    conn.commit()

def _allocated_ips(conn):
    rows = conn.execute("SELECT ip_addr FROM peer_allocations").fetchall()
    return {r["ip_addr"] for r in rows}

def _allocate_ip(conn, device_id: int):
    net = ipaddress.ip_network(WG_CIDR, strict=False)
    used = _allocated_ips(conn)
    # reserve .1 for server; start from .2
    for host in list(net.hosts())[1:]:
        ip = str(host)
        if ip not in used:
            return ip
    return None

def status():
    code, out, err = _wg(["show", WG_IFACE])
    ok = (code == 0)
    return {"success": ok, "interface": WG_IFACE, "wg_show": out if ok else err}

def add_peer(public_key: str, user_id: int, device_id: int|None = None):
    if not device_id:
        return {"success": False, "message": "device_id required"}
    with _db() as conn:
        _ensure_tables(conn)
        # already allocated?
        row = conn.execute("SELECT ip_addr FROM peer_allocations WHERE device_id = ?", (device_id,)).fetchone()
        ip = row["ip_addr"] if row else _allocate_ip(conn, device_id)
        if not ip:
            return {"success": False, "message": "no free IPs left in WG_CIDR"}
        # wg set peer
        code, out, err = _wg(["set", WG_IFACE, "peer", public_key, "allowed-ips", f"{ip}/32"])
        if code != 0:
            return {"success": False, "message": f"wg set failed: {err or out}"}
        # persist (SaveConfig must be true in wg0.conf)
        _wg(["setconf", WG_IFACE, f"/etc/wireguard/{WG_IFACE}.conf"])  # best-effort
        # record
        conn.execute("""
          INSERT INTO peer_allocations (device_id, user_id, public_key, ip_addr)
          VALUES (?,?,?,?)
          ON CONFLICT(device_id) DO UPDATE SET public_key=excluded.public_key, ip_addr=excluded.ip_addr
        """, (device_id, user_id, public_key, ip))
        conn.commit()
        return {"success": True, "ip": ip}

def issue_config(user_id: int, device_id: int):
    """
    Generate a new client keypair, allocate IP, add peer to wg0, return client .conf.
    """
    priv, pub, err = _gen_keypair()
    if err: return {"success": False, "message": err}

    server_pub = _server_public_key()
    if not server_pub:
        return {"success": False, "message": "server public key not found. Ensure wg0 is up or place /etc/wireguard/server_public.key"}

    with _db() as conn:
        _ensure_tables(conn)
        ip = _allocate_ip(conn, device_id)
        if not ip:
            return {"success": False, "message": "no free IPs in WG_CIDR"}
        # add peer
        code, out, err2 = _wg(["set", WG_IFACE, "peer", pub, "allowed-ips", f"{ip}/32"])
        if code != 0:
            return {"success": False, "message": f"wg set failed: {err2 or out}"}
        _wg(["setconf", WG_IFACE, f"/etc/wireguard/{WG_IFACE}.conf"])  # best-effort persist

        conn.execute("""
          INSERT INTO peer_allocations (device_id, user_id, public_key, ip_addr)
          VALUES (?,?,?,?)
          ON CONFLICT(device_id) DO UPDATE SET public_key=excluded.public_key, ip_addr=excluded.ip_addr
        """, (device_id, user_id, pub, ip))
        conn.commit()

    conf = f"""[Interface]
PrivateKey = {priv}
Address = {ip}/32
DNS = {WG_DNS}

[Peer]
PublicKey = {server_pub}
Endpoint = {WG_HOST}:{WG_PORT}
AllowedIPs = {WG_ALLOWED}
PersistentKeepalive = 25
"""
    return {"success": True, "public_key": pub, "config": conf, "ip": ip, "endpoint": f"{WG_HOST}:{WG_PORT}"}
