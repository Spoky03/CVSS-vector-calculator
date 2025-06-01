from flask import Flask, request, jsonify
import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification
import os

app = Flask(__name__)

def load_label_map(path):
    label_map = {}
    with open(path, "r") as f:
        for line in f:
            k, v = line.strip().split(":")
            label_map[int(v)] = k
    return label_map

def predict_metric(description, metric_name, models_dir="./cvss_models"):
    model_path = f"{models_dir}/{metric_name}"
    
    # Load model and tokenizer
    model = AutoModelForSequenceClassification.from_pretrained(model_path)
    tokenizer = AutoTokenizer.from_pretrained(model_path)
    model.eval()

    # Load label mapping
    label_map = load_label_map(f"{model_path}/label_map.txt")
    
    # Tokenization
    inputs = tokenizer(description, return_tensors="pt", truncation=True, padding=True)
    
    # Prediction
    with torch.no_grad():
        outputs = model(**inputs)
        predicted_id = torch.argmax(outputs.logits, dim=1).item()

    return label_map[predicted_id]

CVSS_METRICS = ["AV", "AC", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA"]

def predict_all_metrics(description, models_dir="./cvss_models"):
    results = {}
    for metric in CVSS_METRICS:
        try:
            value = predict_metric(description, metric, models_dir)
            results[metric] = value
        except Exception as e:
            results[metric] = f"Error: {e}"
    return results

@app.route('/api/predict', methods=['POST'])
def predict_cvss():
    try:
        # Get description from request
        data = request.get_json()
        
        if not data or 'description' not in data:
            return jsonify({'error': 'Description is required'}), 400
        
        description = data['description']
        
        if not description.strip():
            return jsonify({'error': 'Description cannot be empty'}), 400
        
        # Get models directory from request or use default
        models_dir = data.get('models_dir', './cvss_models')
        
        # Check if models directory exists
        if not os.path.exists(models_dir):
            return jsonify({'error': f'Models directory not found: {models_dir}'}), 404
        
        # Predict all metrics
        results = predict_all_metrics(description, models_dir)
        
        return jsonify({
            'description': description,
            'cvss_flags': results,
            'status': 'success'
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/predict/metric', methods=['POST'])
def predict_single_metric():
    try:
        # Get data from request
        data = request.get_json()
        
        if not data or 'description' not in data or 'metric' not in data:
            return jsonify({'error': 'Description and metric are required'}), 400
        
        description = data['description']
        metric = data['metric']
        
        if not description.strip():
            return jsonify({'error': 'Description cannot be empty'}), 400
        
        if metric not in CVSS_METRICS:
            return jsonify({'error': f'Invalid metric. Valid metrics: {CVSS_METRICS}'}), 400
        
        # Get models directory from request or use default
        models_dir = data.get('models_dir', './cvss_models')
        
        # Check if models directory exists
        if not os.path.exists(models_dir):
            return jsonify({'error': f'Models directory not found: {models_dir}'}), 404
        
        # Predict single metric
        result = predict_metric(description, metric, models_dir)
        
        return jsonify({
            'description': description,
            'metric': metric,
            'value': result,
            'status': 'success'
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/metrics/all', methods=['GET'])
def get_all_metrics_info():
    """Return detailed information about all CVSS metrics"""
    metrics_info = {
        "AV": {
            "name": "Attack Vector",
            "description": "Reflects the context by which vulnerability exploitation is possible",
            "values": ["N", "A", "L", "P"]
        },
        "AC": {
            "name": "Attack Complexity", 
            "description": "Describes the conditions beyond the attacker's control",
            "values": ["L", "H"]
        },
        "PR": {
            "name": "Privileges Required",
            "description": "Describes the level of privileges an attacker must possess",
            "values": ["N", "L", "H"]
        },
        "UI": {
            "name": "User Interaction",
            "description": "Captures the requirement for a human user to participate in the attack",
            "values": ["N", "R"]
        },
        "VC": {
            "name": "Vulnerability Confidentiality Impact",
            "description": "Measures the impact to the confidentiality of the information",
            "values": ["N", "L", "H"]
        },
        "VI": {
            "name": "Vulnerability Integrity Impact", 
            "description": "Measures the impact to integrity of a successfully exploited vulnerability",
            "values": ["N", "L", "H"]
        },
        "VA": {
            "name": "Vulnerability Availability Impact",
            "description": "Measures the impact to the availability of the impacted component",
            "values": ["N", "L", "H"]
        },
        "SC": {
            "name": "Subsequent Confidentiality Impact",
            "description": "Measures the impact to the confidentiality of the subsequent system",
            "values": ["N", "L", "H"]
        },
        "SI": {
            "name": "Subsequent Integrity Impact",
            "description": "Measures the impact to the integrity of the subsequent system", 
            "values": ["N", "L", "H"]
        },
        "SA": {
            "name": "Subsequent Availability Impact",
            "description": "Measures the impact to the availability of the subsequent system",
            "values": ["N", "L", "H"]
        }
    }
    
    return jsonify({
        "total_metrics": len(CVSS_METRICS),
        "metrics": metrics_info,
        "status": "success"
    })

@app.route('/api/predict/all', methods=['POST'])
def predict_all_cvss_metrics():
    """Alternative endpoint name for predicting all metrics"""
    return predict_cvss()

@app.route('/api/health', methods=['GET'])
def health_check():
    return jsonify({'status': 'healthy', 'message': 'CVSS Prediction API is running'})

@app.route('/api/metrics', methods=['GET'])
def get_available_metrics():
    return jsonify({'available_metrics': CVSS_METRICS})

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=3000)