
from flask import Flask, jsonify, request, render_template
import sqlite3, random, time, threading, queue

app = Flask(__name__)
DB = "ngfw.db"

APPS = ["HTTPS", "DNS", "HTTP", "SMB", "SSH", "RDP", "FTP", "Zoom",
        "WhatsApp", "BitTorrent", "Telegram", "Netflix"]
IPS_POOL = [f"10.20.{random.randint(0,254)}.{random.randint(2,254)}" for _ in range(30)]
EXT_POOL = [f"{random.randint(80,203)}.{random.randint(0,254)}.{random.randint(0,254)}.{random.randint(1,254)}" for _ in range(40)]

def db():
    con = sqlite3.connect(DB)
    con.row_factory = sqlite3.Row
    return con

def init_db():
    con = db()
    con.executescript("""
    CREATE TABLE IF NOT EXISTS rules(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT, src TEXT, dst TEXT, app TEXT,
        action TEXT CHECK(action IN ('ALLOW','DENY')),
        ips INTEGER DEFAULT 0, webfilter INTEGER DEFAULT 0,
        enabled INTEGER DEFAULT 1, hits INTEGER DEFAULT 0,
        created REAL);
    CREATE TABLE IF NOT EXISTS logs(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts REAL, src TEXT, dst TEXT, app TEXT,
        action TEXT, threat TEXT, bytes INTEGER);
    CREATE INDEX IF NOT EXISTS idx_logs_ts ON logs(ts);
    """)
    if con.execute("SELECT COUNT(*) c FROM rules").fetchone()["c"] == 0:
        seed = [
            ("LAN a Internet - Web segura", "10.20.0.0/16", "any", "HTTPS", "ALLOW", 1, 1),
            ("Bloquear P2P", "any", "any", "BitTorrent", "DENY", 1, 0),
            ("Permitir DNS", "any", "8.8.8.8", "DNS", "ALLOW", 0, 0),
            ("Bloquear RDP externo", "any", "10.20.0.0/16", "RDP", "DENY", 1, 0),
            ("Streaming controlado", "10.20.0.0/16", "any", "Netflix", "ALLOW", 0, 1),
        ]
        con.executemany("INSERT INTO rules(name,src,dst,app,action,ips,webfilter,enabled,created) VALUES(?,?,?,?,?,?,?,1,?)",
                        [(*r, time.time()) for r in seed])
    con.commit(); con.close()

# ---------- Motor NGFW ----------
def ip_in_net(ip, net):
    if net in ("any", "*"): return True
    if "/" in net:
        a, bits = net.split("/"); bits = int(bits)
        ia = int.from_bytes(map(int, ip.split(".")), "big")
        na = int.from_bytes(map(int, a.split(".")), "big")
        mask = (0xFFFFFFFF << (32-bits)) & 0xFFFFFFFF
        return (ia & mask) == (na & mask)
    return ip == net

def evaluate(src, dst, app):
    con = db()
    rules = con.execute("SELECT * FROM rules WHERE enabled=1 ORDER BY id").fetchall()
    for r in rules:
        if ip_in_net(src, r["src"]) and ip_in_net(dst, r["dst"]) \
           and (r["app"] in ("any", "*", app)):
            con.execute("UPDATE rules SET hits=hits+1 WHERE id=?", (r["id"],))
            con.commit(); con.close()
            return dict(r)
    con.close()
    return None  # default deny

THREATS = ["-", "-", "-", "SQLi attempt", "Malware.C2 beacon", "Port scan",
           "Phishing URL", "Ransomware signature", "Anomaly: entropy spike", "-"]

def log_event(src, dst, app, action, threat, nbytes):
    con = db()
    con.execute("INSERT INTO logs(ts,src,dst,app,action,threat,bytes) VALUES(?,?,?,?,?,?,?)",
                (time.time(), src, dst, app, action, threat, nbytes))
    con.execute("DELETE FROM logs WHERE id NOT IN (SELECT id FROM logs ORDER BY id DESC LIMIT 500)")
    con.commit(); con.close()

def gen_traffic():
    app_ = random.choices(APPS, weights=[30,15,12,4,6,5,3,6,7,3,5,4])[0]
    internal = random.random() < 0.55
    src = random.choice(IPS_POOL) if internal else random.choice(EXT_POOL)
    dst = random.choice(EXT_POOL) if internal else random.choice(IPS_POOL)
    rule = evaluate(src, dst, app_)
    if rule is None:
        action, threat = "DENY", "-"
    else:
        action = rule["action"]
        threat = "-" if action == "ALLOW" and not rule["ips"] else random.choice(THREATS)
        if action == "DENY": threat = random.choice(THREATS)
    if threat != "-" and action == "ALLOW":
        action = "DENY"   # IPS in-line bloquea
    nbytes = random.randint(400, 900_000)
    log_event(src, dst, app_, action, threat, nbytes)
    return {"src": src, "dst": dst, "app": app_, "action": action,
            "threat": threat, "bytes": nbytes}

# ---------- Generador de trafico en segundo plano ----------
stop_flag = threading.Event()
def traffic_loop():
    while not stop_flag.is_set():
        for _ in range(random.randint(1, 4)):
            gen_traffic()
        time.sleep(random.uniform(0.4, 1.2))

# ---------- API ----------
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/stats")
def stats():
    con = db()
    s = {}
    s["total"] = con.execute("SELECT COUNT(*) c FROM logs").fetchone()["c"]
    s["blocked"] = con.execute("SELECT COUNT(*) c FROM logs WHERE action='DENY'").fetchone()["c"]
    s["threats"] = con.execute("SELECT COUNT(*) c FROM logs WHERE threat!='-'").fetchone()["c"]
    s["active_rules"] = con.execute("SELECT COUNT(*) c FROM rules WHERE enabled=1").fetchone()["c"]
    s["rules_total"] = con.execute("SELECT COUNT(*) c FROM rules").fetchone()["c"]
    s["apps"] = [dict(r) for r in con.execute(
        "SELECT app, COUNT(*) n, SUM(bytes) b FROM logs GROUP BY app ORDER BY n DESC LIMIT 8")]
    s["timeline"] = [dict(r) for r in con.execute(
        """SELECT strftime('%H:%M', ts, 'unixepoch') t,
           SUM(CASE WHEN action='ALLOW' THEN 1 ELSE 0 END) allow,
           SUM(CASE WHEN action='DENY' THEN 1 ELSE 0 END) deny
           FROM logs GROUP BY cast(ts/60 AS INT) ORDER BY t DESC LIMIT 30""")]
    s["timeline"].reverse()
    s["top_threats"] = [dict(r) for r in con.execute(
        "SELECT threat, COUNT(*) n FROM logs WHERE threat!='-' GROUP BY threat ORDER BY n DESC LIMIT 6")]
    con.close()
    return jsonify(s)

@app.route("/api/rules", methods=["GET", "POST"])
def rules():
    con = db()
    if request.method == "POST":
        d = request.json
        con.execute("""INSERT INTO rules(name,src,dst,app,action,ips,webfilter,enabled,created)
                       VALUES(?,?,?,?,?,?,?,1,?)""",
                    (d["name"], d["src"], d["dst"], d["app"], d["action"],
                     int(d.get("ips", 0)), int(d.get("webfilter", 0)), time.time()))
        con.commit(); con.close()
        return jsonify(ok=True), 201
    rs = [dict(r) for r in con.execute("SELECT * FROM rules ORDER BY id")]
    con.close()
    return jsonify(rs)

@app.route("/api/rules/<int:rid>", methods=["PUT", "DELETE"])
def rule_op(rid):
    con = db()
    if request.method == "DELETE":
        con.execute("DELETE FROM rules WHERE id=?", (rid,))
    else:
        d = request.json
        if "enabled" in d:
            con.execute("UPDATE rules SET enabled=? WHERE id=?", (int(d["enabled"]), rid))
        else:
            con.execute("""UPDATE rules SET name=?,src=?,dst=?,app=?,action=?,ips=?,webfilter=?
                           WHERE id=?""",
                        (d["name"], d["src"], d["dst"], d["app"], d["action"],
                         int(d.get("ips", 0)), int(d.get("webfilter", 0)), rid))
    con.commit(); con.close()
    return jsonify(ok=True)

@app.route("/api/logs")
def logs():
    con = db()
    rs = [dict(r) for r in con.execute(
        "SELECT * FROM logs ORDER BY id DESC LIMIT 40")]
    con.close()
    return jsonify(rs)

@app.route("/api/test", methods=["POST"])
def test():
    d = request.json or {}
    src = d.get("src", random.choice(IPS_POOL))
    dst = d.get("dst", random.choice(EXT_POOL))
    app_ = d.get("app", random.choice(APPS))
    rule = evaluate(src, dst, app_)
    result = {
        "src": src, "dst": dst, "app": app_,
        "verdict": "ALLOW" if rule and rule["action"] == "ALLOW" else "DENY",
        "matched_rule": rule["name"] if rule else "(default-deny)",
        "inspected_by": []
    }
    if rule:
        if rule["ips"]: result["inspected_by"].append("IPS")
        if rule["webfilter"]: result["inspected_by"].append("WebFilter")
    return jsonify(result)

if __name__ == "__main__":
    init_db()
    threading.Thread(target=traffic_loop, daemon=True).start()
    app.run(host="0.0.0.0", port=5000, debug=False)
