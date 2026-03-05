"""
CTI Platform - Flask Backend API
Run: python app.py
Open: http://localhost:5000
"""

from flask import Flask, jsonify, request
import json, os, sys
from datetime import datetime
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from data_gen       import generate_threat_feed, save_data
from ioc_extractor  import IOCExtractor, SAMPLE_REPORT
from ml_prioritizer import ThreatPrioritizer

app = Flask(__name__, template_folder="templates")

prioritizer    = ThreatPrioritizer()
prioritized_data = []


def initialize():
    global prioritized_data
    os.makedirs("data", exist_ok=True)

    if not os.path.exists("data/threat_feed.json"):
        print("📡 Generating threat feed...")
        threats = generate_threat_feed(200)
        save_data(threats)

    with open("data/threat_feed.json") as f:
        threats = json.load(f)

    print("🤖 Training ML model...")
    prioritizer.train(threats)
    prioritized_data = prioritizer.prioritize(threats)

    with open("data/prioritized_threats.json","w") as f:
        json.dump(prioritized_data, f, indent=2)

    print(f"✅ CTI Platform ready! {len(prioritized_data)} threats loaded.")


@app.route("/")
def index():
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "templates", "dashboard.html")
    with open(path, encoding="utf-8") as f:
        return f.read()


@app.route("/api/stats")
def stats():
    sev   = Counter(t["severity"]        for t in prioritized_data)
    types = Counter(t["threat_type"]     for t in prioritized_data)
    pri   = Counter(t["ml_priority"]     for t in prioritized_data)
    sta   = Counter(t["status"]          for t in prioritized_data)
    actors= Counter(t["threat_actor"]    for t in prioritized_data if t["threat_actor"] != "Unknown")
    sects = Counter(t["targeted_sector"] for t in prioritized_data)
    ctry  = Counter(t["origin_country"]  for t in prioritized_data)
    avg_r = round(sum(t["risk_score"] for t in prioritized_data) / max(len(prioritized_data),1), 1)

    return jsonify({
        "total_threats":    len(prioritized_data),
        "critical_threats": pri.get("P1_CRITICAL", 0),
        "active_threats":   sta.get("Active", 0),
        "avg_risk_score":   avg_r,
        "severity_distribution": dict(sev),
        "threat_types":     dict(types.most_common(6)),
        "priority_distribution": dict(pri),
        "status_distribution":   dict(sta),
        "top_actors":       dict(actors.most_common(5)),
        "targeted_sectors": dict(sects.most_common(6)),
        "origin_countries": dict(ctry.most_common(8)),
        "last_updated":     datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    })


@app.route("/api/threats")
def get_threats():
    limit    = int(request.args.get("limit", 50))
    severity = request.args.get("severity", "")
    priority = request.args.get("priority", "")
    status   = request.args.get("status", "")

    data = prioritized_data
    if severity: data = [t for t in data if t["severity"]    == severity]
    if priority: data = [t for t in data if t["ml_priority"] == priority]
    if status:   data = [t for t in data if t["status"]      == status]

    keys = ["id","timestamp","threat_type","severity","risk_score","ml_priority",
            "ml_confidence","threat_actor","origin_country","targeted_sector",
            "ioc_count","status","action","source","tags","confidence"]
    return jsonify({
        "threats": [{k: t.get(k) for k in keys} for t in data[:limit]],
        "total":   len(data)
    })


@app.route("/api/threat/<tid>")
def threat_detail(tid):
    for t in prioritized_data:
        if t["id"] == tid: return jsonify(t)
    return jsonify({"error": "Not found"}), 404


@app.route("/api/extract_ioc", methods=["POST"])
def extract_ioc():
    text = (request.get_json() or {}).get("text", SAMPLE_REPORT)
    ext  = IOCExtractor()
    raw  = ext.extract(text)
    enr  = ext.enrich(raw)
    return jsonify({
        "total_iocs": sum(len(v) for v in raw.values()),
        "iocs":       enr,
        "raw_counts": {k: len(v) for k, v in raw.items()}
    })


@app.route("/api/timeline")
def timeline():
    daily = Counter(t["timestamp"][:10] for t in prioritized_data)
    dates = sorted(daily)[-30:]
    return jsonify({"dates": dates, "counts": [daily[d] for d in dates]})


@app.route("/api/refresh", methods=["POST"])
def refresh():
    global prioritized_data
    threats = generate_threat_feed(200)
    save_data(threats)
    prioritizer.train(threats)
    prioritized_data = prioritizer.prioritize(threats)
    return jsonify({"status": "ok", "count": len(prioritized_data)})


if __name__ == "__main__":
    initialize()
    print("\n" + "="*45)
    print("🚀 CTI Dashboard → http://localhost:5000")
    print("="*45 + "\n")
    app.run(debug=True, port=5000)