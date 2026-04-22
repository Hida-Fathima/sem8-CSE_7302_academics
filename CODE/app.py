import json
import os
from flask import Flask, render_template, jsonify, request
from werkzeug.utils import secure_filename
from data_gen import generate_log
from ml_engine import detector
from ai_analyst import analyze_threat
from config import UPLOAD_FOLDER, MAX_CONTENT_LENGTH
from security import allowed_file, sanitize_input

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH

# State
logs_store = []
alerts_store = []
mode = "LIVE" # LIVE or FILE

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/feed')
def get_feed():
    global logs_store, alerts_store, mode
    
    if mode == "LIVE":
        # 1. Generate new log
        new_log = generate_log()
        
        # 2. Train/Update ML (Simulated Online Learning)
        if len(logs_store) > 50 and not detector.is_trained:
            detector.train(logs_store)
        
        # 3. Detect Anomaly
        is_anomaly = detector.predict(new_log) == -1
        new_log['ml_anomaly'] = is_anomaly # Add flag for UI
        
        # 4. If High Severity or ML Anomaly -> Send to AI
        if new_log['severity'] == "CRITICAL" or is_anomaly:
            ai_res = analyze_threat(new_log)
            alerts_store.insert(0, {"log": new_log, "analysis": ai_res})
            
        logs_store.insert(0, new_log)
        if len(logs_store) > 100: logs_store.pop()
        
    return jsonify({"logs": logs_store, "alerts": alerts_store, "mode": mode})

@app.route('/upload', methods=['POST'])
def upload_file():
    global logs_store, alerts_store, mode
    
    if 'file' not in request.files:
        return jsonify({"error": "No file part"}), 400
        
    file = request.files['file']
    
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        
        # Switch mode
        mode = "FILE"
        logs_store = [] # Clear live logs
        alerts_store = []
        
        # Parse File (Assumes line-by-line JSON for simplicity in demo)
        # You can add logic here to parse CSV or TXT logs
        with open(filepath, 'r') as f:
            for line in f:
                try:
                    # Logic to parse simple text logs or JSON
                    # This is a basic parser for the demo
                    if "{" in line:
                         log = json.loads(line)
                    else:
                        # Fallback for raw text
                        log = {
                            "timestamp": "FromFile", 
                            "severity": "UNKNOWN", 
                            "signature": "Raw Log", 
                            "payload": sanitize_input(line),
                            "source_ip": "0.0.0.0",
                            "status_code": 0
                        }
                    
                    logs_store.append(log)
                    
                    # Run Analysis on File Data
                    if log.get('severity') == "CRITICAL":
                        ai_res = analyze_threat(log)
                        alerts_store.append({"log": log, "analysis": ai_res})
                        
                except Exception as e:
                    print(f"Skipping bad line: {e}")
                    
        return jsonify({"success": True, "count": len(logs_store)})
        
    return jsonify({"error": "Invalid file"}), 400

@app.route('/reset')
def reset_mode():
    global mode, logs_store, alerts_store
    mode = "LIVE"
    logs_store = []
    alerts_store = []
    return jsonify({"success": True})
@app.route('/api/analyze_on_demand', methods=['POST'])
def analyze_on_demand():
    """
    Endpoint for the 'Click-to-Analyze' feature.
    Receives a specific log from the frontend and runs AI on it.
    """
    try:
        log_data = request.json
        # Run the AI (reuses your existing ai_analyst.py)
        analysis_result = analyze_threat(log_data)
        return jsonify({"success": True, "analysis": analysis_result})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, port=5000)