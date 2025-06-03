import pandas as pd
import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
import numpy as np
import os
from collections import defaultdict
import matplotlib.pyplot as plt
import seaborn as sns

def load_label_map(path):
    """Load label mapping from file"""
    label_map = {}
    with open(path, "r") as f:
        for line in f:
            k, v = line.strip().split(":")
            label_map[int(v)] = k
    return label_map

def predict_metric(description, metric_name, models_dir="./cvss_models"):
    """Predict a single CVSS metric"""
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

def map_cvss_values_to_abbreviations(value):
    """Map full CVSS values to their abbreviations"""
    mapping = {
        # Attack Vector
        'NETWORK': 'N',
        'ADJACENT': 'A', 
        'LOCAL': 'L',
        'PHYSICAL': 'P',
        
        # Attack Complexity
        'LOW': 'L',
        'HIGH': 'H',
        
        # Privileges Required
        'NONE': 'N',
        
        # User Interaction
        'REQUIRED': 'R',
        
        # Impact values
        'MEDIUM': 'M',
        
        # Default for NOT_DEFINED and others
        'NOT_DEFINED': 'X'
    }
    
    return mapping.get(value, value)

def test_model_accuracy(csv_file_path, models_dir="./cvss_models"):
    """Test model accuracy on CVSSv4 data"""
    
    # Load data
    print(f"Loading data from {csv_file_path}...")
    df = pd.read_csv(csv_file_path)
    
    # Filter out rows without description
    df = df.dropna(subset=['description'])
    
    print(f"Testing on {len(df)} samples")
    
    # Define metrics to test and their corresponding CSV columns
    metric_columns = {
        "AV": "attackVector",
        "AC": "attackComplexity", 
        "PR": "privilegesRequired",
        "UI": "userInteraction",
        "VC": "vulnConfidentialityImpact",
        "VI": "vulnIntegrityImpact", 
        "VA": "vulnAvailabilityImpact",
        "SC": "subConfidentialityImpact",
        "SI": "subIntegrityImpact",
        "SA": "subAvailabilityImpact"
    }
    
    results = {}
    detailed_results = defaultdict(list)
    
    for metric, column_name in metric_columns.items():
        print(f"\nTesting metric: {metric} (using column: {column_name})")
        
        # Check if model exists
        model_path = f"{models_dir}/{metric}"
        if not os.path.exists(model_path):
            print(f"Model for {metric} not found at {model_path}")
            continue
            
        # Check if column exists in CSV
        if column_name not in df.columns:
            print(f"Column {column_name} not found in CSV")
            continue
        
        y_true = []
        y_pred = []
        
        # Process each row
        for idx, row in df.iterrows():
            description = row['description']
            actual_value_full = row[column_name]
            
            # Skip if actual value is missing or NOT_DEFINED
            if pd.isna(actual_value_full) or actual_value_full == 'NOT_DEFINED':
                continue
                
            # Map full value to abbreviation
            actual_value = map_cvss_values_to_abbreviations(actual_value_full)
            
            try:
                # Get prediction
                predicted_value = predict_metric(description, metric, models_dir)
                
                y_true.append(actual_value)
                y_pred.append(predicted_value)
                
                detailed_results[metric].append({
                    'cve_id': row.get('cve_id', f'row_{idx}'),
                    'description': description[:100] + '...' if len(description) > 100 else description,
                    'actual_full': actual_value_full,
                    'actual': actual_value,
                    'predicted': predicted_value,
                    'correct': actual_value == predicted_value
                })
                
            except Exception as e:
                print(f"Error predicting {metric} for row {idx}: {e}")
                continue
        
        if y_true and y_pred:
            # Calculate accuracy
            accuracy = accuracy_score(y_true, y_pred)
            results[metric] = {
                'accuracy': accuracy,
                'total_samples': len(y_true),
                'y_true': y_true,
                'y_pred': y_pred
            }
            
            print(f"{metric} Accuracy: {accuracy:.4f} ({len(y_true)} samples)")
            
            # Print classification report
            print(f"\nClassification Report for {metric}:")
            print(classification_report(y_true, y_pred, zero_division=0))
        else:
            print(f"No valid samples found for metric {metric}")
    
    return results, detailed_results

def plot_confusion_matrices(results, save_plots=True):
    """Plot confusion matrices for each metric"""
    if not results:
        print("No results to plot")
        return
        
    # Calculate number of rows and columns for subplots
    n_metrics = len(results)
    n_cols = min(5, n_metrics)
    n_rows = (n_metrics + n_cols - 1) // n_cols
    
    fig, axes = plt.subplots(n_rows, n_cols, figsize=(4*n_cols, 4*n_rows))
    
    # Handle case where there's only one subplot
    if n_metrics == 1:
        axes = [axes]
    elif n_rows == 1:
        axes = [axes] if n_metrics == 1 else axes
    else:
        axes = axes.flatten()
    
    for idx, (metric, data) in enumerate(results.items()):
        y_true = data['y_true']
        y_pred = data['y_pred']
        
        # Get unique labels
        labels = sorted(list(set(y_true + y_pred)))
        
        # Create confusion matrix
        cm = confusion_matrix(y_true, y_pred, labels=labels)
        
        # Plot
        sns.heatmap(cm, annot=True, fmt='d', ax=axes[idx], 
                   xticklabels=labels, yticklabels=labels)
        axes[idx].set_title(f'{metric} (Acc: {data["accuracy"]:.3f})')
        axes[idx].set_xlabel('Predicted')
        axes[idx].set_ylabel('Actual')
    
    # Hide unused subplots
    for idx in range(len(results), len(axes)):
        axes[idx].set_visible(False)
    
    plt.tight_layout()
    
    if save_plots:
        plt.savefig('confusion_matrices.png', dpi=300, bbox_inches='tight')
        print("Confusion matrices saved as 'confusion_matrices.png'")
    
    plt.show()

def save_detailed_results(detailed_results, filename='detailed_results.csv'):
    """Save detailed results to CSV"""
    all_results = []
    
    for metric, results in detailed_results.items():
        for result in results:
            result['metric'] = metric
            all_results.append(result)
    
    df_results = pd.DataFrame(all_results)
    df_results.to_csv(filename, index=False)
    print(f"Detailed results saved to {filename}")

def print_summary(results):
    """Print overall summary"""
    print("\n" + "="*50)
    print("ACCURACY SUMMARY")
    print("="*50)
    
    total_accuracy = 0
    total_samples = 0
    
    for metric, data in results.items():
        accuracy = data['accuracy']
        samples = data['total_samples']
        
        print(f"{metric:>3}: {accuracy:>6.4f} ({samples:>4} samples)")
        
        total_accuracy += accuracy * samples
        total_samples += samples
    
    if total_samples > 0:
        weighted_avg_accuracy = total_accuracy / total_samples
        print("-" * 30)
        print(f"Weighted Average: {weighted_avg_accuracy:.4f}")
    
    print("="*50)

def analyze_value_distributions(csv_file_path):
    """Analyze the distribution of values in the CSV"""
    df = pd.read_csv(csv_file_path)
    
    metric_columns = {
        "AV": "attackVector",
        "AC": "attackComplexity", 
        "PR": "privilegesRequired",
        "UI": "userInteraction",
        "VC": "vulnConfidentialityImpact",
        "VI": "vulnIntegrityImpact", 
        "VA": "vulnAvailabilityImpact",
        "SC": "subConfidentialityImpact",
        "SI": "subIntegrityImpact",
        "SA": "subAvailabilityImpact"
    }
    
    print("\nValue distributions in CSV:")
    print("="*50)
    
    for metric, column in metric_columns.items():
        if column in df.columns:
            print(f"\n{metric} ({column}):")
            value_counts = df[column].value_counts()
            for value, count in value_counts.items():
                abbrev = map_cvss_values_to_abbreviations(value)
                print(f"  {value} ({abbrev}): {count}")

if __name__ == "__main__":
    # Test the model
    csv_file = "nvd_cvss4_data2.csv"
    models_directory = "./cvss_models"
    
    print("Starting model accuracy testing...")
    
    # Analyze value distributions first
    analyze_value_distributions(csv_file)
    
    # Run accuracy test
    results, detailed_results = test_model_accuracy(csv_file, models_directory)
    
    # Print summary
    if results:
        print_summary(results)
        
        # Save detailed results
        save_detailed_results(detailed_results)
        
        # Plot confusion matrices
        plot_confusion_matrices(results)
    else:
        print("No results to summarize")
    
    print("\nTesting completed!")