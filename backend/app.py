from flask import Flask, jsonify, send_from_directory
from flask_cors import CORS
import threading
import os
import fake_logs
import detector

app = Flask(__name__)
CORS(app, origins="*")

@app.route("/")
def index():
    return send_from_directory("../frontend", "index.html")

@app.route("/alerts")
def alerts():
    return jsonify(detector.detect())

@app.route("/stats")
def stats():
    return jsonify(detector.get_stats())

@app.route("/traffic")
def traffic():
    return jsonify(detector.get_traffic())

if __name__ == "__main__":
    fake_logs.generate()
    t = threading.Thread(target=fake_logs.stream_live, daemon=True)
    t.start()
    print("Server running → http://localhost:5000")
    app.run(debug=False, port=5000, host="0.0.0.0")