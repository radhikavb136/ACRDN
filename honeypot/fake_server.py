from flask import Flask, jsonify, request
import logging

app = Flask("honeypot")

logging.basicConfig(
    filename="hacker_activity.log",
    level=logging.INFO,
    format="%(asctime)s | %(message)s"
)

def log(msg):
    logging.info(msg)
    print(f"[HONEYPOT] {msg}")

FAKE_PAGE = """
<html>
<head><title>Company Internal Portal</title></head>
<body style='font-family:Arial;padding:20px'>
<h2>Internal Network - Admin Portal v2.1</h2>
<p>Welcome to the internal management system</p>
<hr>
<a href='/files'>File Server</a> |
<a href='/users'>User Management</a> |
<a href='/config'>System Config</a> |
<a href='/login'>Admin Login</a>
</body>
</html>
"""

@app.route("/", defaults={"path": ""})
@app.route("/<path:path>", methods=["GET","POST","PUT"])
def catch_all(path):
    ip = request.remote_addr
    log(f"[{ip}] → /{path} ({request.method})")

    if path == "files":
        return jsonify({"files": [
            "employee_records.csv",
            "server_passwords.txt",
            "backup_keys.pem",
            "database_dump.sql"
        ]})

    elif path == "users":
        return jsonify({"users": [
            {"name": "admin",  "role": "superadmin"},
            {"name": "root",   "role": "system"},
            {"name": "backup", "role": "operator"}
        ]})

    elif path == "config":
        return jsonify({
            "server":   "Ubuntu 20.04",
            "version":  "2.1.4",
            "database": "mysql://localhost:3306/prod",
            "status":   "running"
        })

    elif path == "login" and request.method == "POST":
        user = request.form.get("username", "")
        pwd  = request.form.get("password", "")
        log(f"[{ip}] LOGIN ATTEMPT: {user} / {pwd}")
        return jsonify({
            "status": "success",
            "token":  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
        })

    return FAKE_PAGE

def start_honeypot(port=8888):
    print(f"[HONEYPOT] Fake server on port {port}")
    app.run(host="0.0.0.0", port=port,
            debug=False, use_reloader=False)