import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification

def load_label_map(path):
    label_map = {}
    with open(path, "r") as f:
        for line in f:
            k, v = line.strip().split(":")
            label_map[int(v)] = k
    return label_map

def predict_metric(description, metric_name, models_dir="./cvss_models"):
    model_path = f"{models_dir}/{metric_name}"
    
    # Wczytanie modelu i tokenizera
    model = AutoModelForSequenceClassification.from_pretrained(model_path)
    tokenizer = AutoTokenizer.from_pretrained(model_path)
    model.eval()

    # Wczytaj mapowanie etykiet
    label_map = load_label_map(f"{model_path}/label_map.txt")
    
    # Tokenizacja
    inputs = tokenizer(description, return_tensors="pt", truncation=True, padding=True)
    
    # Predykcja
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

desc = """A remote attacker can exploit this vulnerability without authentication, 
resulting in code execution in the context of the root user."""

results = predict_all_metrics(desc)

for metric, value in results.items():
    print(f"{metric}: {value}")