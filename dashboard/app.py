from flask import Flask, render_template_string, jsonify
from flask import Response
import threading
import json

app = Flask("dashboard")

dashboard_state = {
    "connections":     {},
    "graph":           {"nodes": [], "edges": []},
    "best_path":       [],
    "patterns_count":  0,
    "attacks_today":   0,
    "honeypot_active": False
}

clients      = []
clients_lock = threading.Lock()

HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>ACRDN Live Dashboard</title>
    <style>
        * { box-sizing:border-box; margin:0; padding:0; }
        body { font-family:Arial; background:#0d1117;
               color:#fff; padding:20px; }
        h1   { color:#58a6ff; margin-bottom:20px;
               font-size:1.8em; }
        .box { background:#161b22;
               border:1px solid #30363d;
               border-radius:8px; padding:15px;
               margin:10px 0; }
        .box h3 { color:#58a6ff; margin-bottom:12px; }
        .stat   { display:inline-block;
                  margin:10px 25px 10px 0;
                  text-align:center; }
        .stat h2 { font-size:2.5em; margin:0;
                   color:#58a6ff; }
        .stat p  { color:#8b949e; font-size:0.85em; }
        table  { width:100%; border-collapse:collapse; }
        td, th { padding:10px 8px;
                 border-bottom:1px solid #30363d;
                 font-size:0.9em; }
        th     { color:#58a6ff; text-align:left; }
        .path  { font-size:1.4em; color:#58a6ff;
                 letter-spacing:2px; }
        .badge { padding:3px 8px; border-radius:4px;
                 font-size:0.8em; font-weight:bold; }
        .b-normal     { background:#1a3a1a; color:#3fb950; }
        .b-suspicious { background:#3a2a00; color:#d29922; }
        .b-malicious  { background:#3a0a0a; color:#f85149; }
        #status { float:right; font-size:0.8em;
                  color:#3fb950; }
    </style>
</head>
<body>
    <h1>ACRDN Live Dashboard
        <span id="status">CONNECTING...</span>
    </h1>

    <div class="box">
        <h3>System Stats</h3>
        <div class="stat">
            <h2 id="patterns">0</h2>
            <p>Patterns Learned</p>
        </div>
        <div class="stat">
            <h2 id="attacks">0</h2>
            <p>Attacks Today</p>
        </div>
        <div class="stat">
            <h2 id="honeypot" style="color:#3fb950">
                STANDBY</h2>
            <p>Honeypot Status</p>
        </div>
        <div class="stat">
            <h2 id="conncount">0</h2>
            <p>Active IPs</p>
        </div>
    </div>

    <div class="box">
        <h3>Current Best Path (Smart Routing)</h3>
        <p id="bestpath" class="path">Calculating...</p>
    </div>

    <div class="box">
        <h3>Network Graph - Live Load</h3>
        <div id="graph"></div>
    </div>

    <div class="box">
        <h3>Active Connections - Real Time</h3>
        <table>
            <thead>
            <tr>
                <th>IP Address</th>
                <th>Intent</th>
                <th>Score</th>
                <th>Action Taken</th>
            </tr>
            </thead>
            <tbody id="connections"></tbody>
        </table>
    </div>

    <script>
        var evtSource = new EventSource("/stream");

        evtSource.onopen = function() {
            document.getElementById("status").innerText
                = "LIVE";
            document.getElementById("status").style.color
                = "#3fb950";
        };

        evtSource.onerror = function() {
            document.getElementById("status").innerText
                = "RECONNECTING...";
            document.getElementById("status").style.color
                = "#d29922";
        };

        evtSource.onmessage = function(e) {
            try {
                var data = JSON.parse(e.data);
                updateDashboard(data);
            } catch(err) {}
        };

        function updateDashboard(data) {
            document.getElementById("patterns").innerText
                = data.patterns_count || 0;
            document.getElementById("attacks").innerText
                = data.attacks_today || 0;

            var hp = document.getElementById("honeypot");
            if (data.honeypot_active) {
                hp.innerText   = "ACTIVE";
                hp.style.color = "#f85149";
            } else {
                hp.innerText   = "STANDBY";
                hp.style.color = "#3fb950";
            }

            var count = Object.keys(
                data.connections || {}
            ).length;
            document.getElementById("conncount")
                .innerText = count;

            if (data.best_path && data.best_path.length) {
                document.getElementById("bestpath")
                    .innerText
                    = data.best_path.join(" -> ");
            }

            var ghtml = "<table><tr>" +
                "<th>From</th><th>To</th>" +
                "<th>Load</th><th>Cost</th>" +
                "<th>Status</th></tr>";
            (data.graph.edges || []).forEach(function(e) {
                var color  = e.load > 60 ? "#f85149" :
                             e.load > 30 ? "#d29922"
                                         : "#3fb950";
                var status = e.load > 60 ? "CONGESTED" :
                             e.load > 30 ? "BUSY"
                                         : "FREE";
                ghtml += "<tr><td>" + e.src +
                    "</td><td>" + e.dst +
                    "</td><td style='color:" +
                    color + "'>" + e.load + "%" +
                    "</td><td>" + e.weight +
                    "</td><td style='color:" +
                    color + "'>" + status +
                    "</td></tr>";
            });
            ghtml += "</table>";
            document.getElementById("graph").innerHTML
                = ghtml;

            var html  = "";
            var conns = data.connections || {};
            for (var ip in conns) {
                var c      = conns[ip];
                var intent = c.intent || "NORMAL";
                var cls    = intent.toLowerCase();
                var action =
                    intent === "MALICIOUS"  ?
                        "Redirected to Honeypot" :
                    intent === "SUSPICIOUS" ?
                        "Monitored Path + Delay" :
                        "Best Path";
                html += "<tr>" +
                    "<td>" + ip + "</td>" +
                    "<td><span class='badge b-" +
                    cls + "'>" + intent +
                    "</span></td>" +
                    "<td>" + (c.score || 0) +
                    "/100</td>" +
                    "<td>" + action +
                    "</td></tr>";
            }
            if (html === "") {
                html = "<tr><td colspan='4' " +
                    "style='color:#8b949e'>" +
                    "Waiting for traffic..." +
                    "</td></tr>";
            }
            document.getElementById("connections")
                .innerHTML = html;
        }

        // Polling backup every 2s
        setInterval(function() {
            fetch("/state")
                .then(function(r) { return r.json(); })
                .then(function(data) {
                    updateDashboard(data);
                })
                .catch(function() {});
        }, 2000);
    </script>
</body>
</html>
"""

@app.route("/")
def index():
    return render_template_string(HTML)

@app.route("/state")
def state():
    return jsonify(dashboard_state)

@app.route("/stream")
def stream():
    import queue

    def event_stream():
        q = queue.Queue()
        with clients_lock:
            clients.append(q)
        try:
            yield f"data: {json.dumps(dashboard_state)}\n\n"
            while True:
                try:
                    msg = q.get(timeout=25)
                    yield f"data: {msg}\n\n"
                except:
                    yield f"data: {json.dumps(dashboard_state)}\n\n"
        except (GeneratorExit, Exception):
            pass
        finally:
            with clients_lock:
                try:
                    clients.remove(q)
                except:
                    pass

    return Response(
        event_stream(),
        mimetype="text/event-stream",
        headers={
            "Cache-Control":     "no-cache",
            "X-Accel-Buffering": "no"
        }
    )

def update_dashboard(new_state):
    dashboard_state.update(new_state)
    msg = json.dumps(dashboard_state)
    with clients_lock:
        dead = []
        for q in list(clients):
            try:
                q.put_nowait(msg)
            except:
                dead.append(q)
        for q in dead:
            try:
                clients.remove(q)
            except:
                pass

def start_dashboard(port=5000):
    print(f"[DASHBOARD] Running on "
          f"http://localhost:{port}")
    app.run(
        host="0.0.0.0",
        port=port,
        debug=False,
        use_reloader=False,
        threaded=True
    )
