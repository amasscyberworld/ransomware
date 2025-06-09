
from flask import Flask, request, jsonify
import os
import hashlib
import requests
import joblib
import numpy as np
from werkzeug.utils import secure_filename

app = Flask(__name__)

MODEL_PATH = "model/ransomware_model.pkl"
model = None
if os.path.exists(MODEL_PATH):
    model = joblib.load(MODEL_PATH)
else:
    print("[WARNING] ML model not found. AI detection will be disabled.")

VT_API_KEY = "YOUR_VIRUSTOTAL_API_KEY"
VT_URL = "https://www.virustotal.com/api/v3/files/{}"

UPLOAD_FOLDER = "test_files"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def calculate_entropy(file_path):
    with open(file_path, "rb") as f:
        data = f.read()
    if not data:
        return 0
    from math import log2
    prob = [float(data.count(byte)) / len(data) for byte in set(data)]
    entropy = -sum(p * log2(p) for p in prob)
    return round(entropy, 2)

def get_file_features(file_path):
    size_kb = os.path.getsize(file_path) / 1024
    entropy = calculate_entropy(file_path)
    ext = os.path.splitext(file_path)[1][1:].lower()
    return [entropy, size_kb, ext]

def check_virustotal(file_path):
    with open(file_path, "rb") as f:
        res = requests.post("https://www.virustotal.com/api/v3/files",
                             headers={"x-apikey": VT_API_KEY},
                             files={"file": f})
    if res.status_code == 200:
        file_id = res.json().get("data", {}).get("id")
        report = requests.get(VT_URL.format(file_id),
                              headers={"x-apikey": VT_API_KEY})
        return report.json()
    return {"error": "VirusTotal scan failed"}

@app.route("/analyze", methods=["POST"])
def analyze_file():
    if "file" not in request.files:
        return jsonify({"error": "No file provided"}), 400

    file = request.files["file"]
    filename = secure_filename(file.filename)
    file_path = os.path.join(UPLOAD_FOLDER, filename)
    file.save(file_path)

    entropy, size_kb, ext = get_file_features(file_path)
    ext_map = {"exe": 0, "pdf": 1, "docx": 2, "jpg": 3, "png": 4, "txt": 5}
    ext_encoded = ext_map.get(ext, -1)

    if ext_encoded == -1:
        return jsonify({"error": f"Unsupported extension: {ext}"}), 400

    result = {
        "filename": filename,
        "entropy": entropy,
        "size_kb": round(size_kb, 2),
        "extension": ext
    }

    if model:
        X = np.array([[entropy, size_kb, ext_encoded]])
        prediction = model.predict(X)[0]
        result["prediction"] = "Ransomware" if prediction == 1 else "Benign"
    else:
        result["prediction"] = "Model Not Available"

    result["virustotal"] = check_virustotal(file_path)
    return jsonify(result)

if __name__ == "__main__":
    app.run(debug=True, port=5000)
