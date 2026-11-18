from flask import Flask, render_template, jsonify
import random

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/stats')
def api_stats():
    # Simulated system metrics for NetPulse Dashboard
    return jsonify({
        "cpu_usage": round(random.uniform(15.0, 65.0), 1),
        "memory_usage": round(random.uniform(40.0, 85.0), 1),
        "network_latency": random.randint(12, 45),
        "active_connections": random.randint(120, 340),
        "status": "SECURE"
    })

if __name__ == '__main__':
    app.run(debug=True, port=5000)
