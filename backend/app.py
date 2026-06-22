from flask import Flask, jsonify
from flask_cors import CORS
import threading
import fake_logs
import detector

app = Flask(__name__)
CORS(app)

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
    # Seed logs first
    fake_logs.generate()
    # Start live log stream in background
    t = threading.Thread(target=fake_logs.stream_live, daemon=True)
    t.start()
    print("Server running → http://localhost:5000")
    app.run(debug=False, port=5000)