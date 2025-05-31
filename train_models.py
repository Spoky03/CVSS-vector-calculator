import pandas as pd
import os
from datasets import Dataset
from transformers import (
    AutoTokenizer,
    AutoModelForSequenceClassification,
    TrainingArguments,
    Trainer
)
import torch

# data path
CSV_PATH = "nvd_cvss4_data.csv"
TEXT_COLUMN = "description"

CVSS_METRICS = ["AV", "AC", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA"]

METRIC_LABELS = {
    "AV": ["N", "A", "L", "P"],
    "AC": ["L", "H"],
    "AT": ["N", "P"],
    "PR": ["N", "L", "H"],
    "UI": ["N", "P", "A"],
    "VC": ["H", "L", "N"],
    "VI": ["H", "L", "N"],
    "VA": ["H", "L", "N"],
    "SC": ["H", "L", "N"],
    "SI": ["H", "L", "N"],
    "SA": ["H", "L", "N"],
}

METRIC_TO_COLUMN = {
    "AV": "attackVector",
    "AC": "attackComplexity",
    "AT": "attackRequirements",
    "PR": "privilegesRequired",
    "UI": "userInteraction",
    "VC": "vulnConfidentialityImpact",
    "VI": "vulnIntegrityImpact",
    "VA": "vulnAvailabilityImpact",
    "SC": "subConfidentialityImpact",
    "SI": "subIntegrityImpact",
    "SA": "subAvailabitilyImpact",
}

# Training params
MODEL_NAME = "bert-base-uncased"
EPOCHS = 4
BATCH_SIZE = 16
OUTPUT_DIR = "./cvss_models"

os.makedirs(OUTPUT_DIR, exist_ok=True)

# Mapping labels to ID
def create_label_map(labels):
    return {label: idx for idx, label in enumerate(labels)}

def first_letter(string: str):
    return string[0]

tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)

df = pd.read_csv(CSV_PATH)

# Training for each metric
for metric in CVSS_METRICS:
    print(f"\nTraining model for {metric} metric")

    metric_col = METRIC_TO_COLUMN[metric]
    label_set = METRIC_LABELS[metric]
    label_map = create_label_map(label_set)
    df_metric = df[[TEXT_COLUMN, metric_col]].dropna()
    df_metric["label"] = df_metric[metric_col].map(first_letter).map(label_map)

    # Convert to Hugging Face Dataset
    dataset = Dataset.from_pandas(df_metric[[TEXT_COLUMN, "label"]])
    dataset = dataset.train_test_split(test_size=0.2)

    def tokenize(batch):
        return tokenizer(batch[TEXT_COLUMN], truncation=True, padding="max_length")
    
    tokenized = dataset.map(tokenize, batched=True)

    # Model klasyfikacji
    model = AutoModelForSequenceClassification.from_pretrained(
        MODEL_NAME,
        num_labels=len(label_set)
    )

    # Argumenty treningowe
    args = TrainingArguments(
        output_dir=f"{OUTPUT_DIR}/{metric}",
        eval_strategy="epoch",
        save_strategy="epoch",
        num_train_epochs=EPOCHS,
        per_device_train_batch_size=BATCH_SIZE,
        per_device_eval_batch_size=BATCH_SIZE,
        learning_rate=2e-5,
        weight_decay=0.01,
        logging_dir=f"{OUTPUT_DIR}/{metric}/logs",
        logging_steps=10,
        save_total_limit=1,
        load_best_model_at_end=True
    )

    # Trainer
    trainer = Trainer(
        model=model,
        args=args,
        train_dataset=tokenized["train"],
        eval_dataset=tokenized["test"],
        tokenizer=tokenizer
    )

    # Trening
    trainer.train()

    # Zapis modelu i tokenizera
    save_path = f"{OUTPUT_DIR}/{metric}"
    model.save_pretrained(save_path)
    tokenizer.save_pretrained(save_path)

    # Zapis label_map do pliku
    with open(os.path.join(save_path, "label_map.txt"), "w") as f:
        for k, v in label_map.items():
            f.write(f"{k}:{v}\n")

print("\nTraining complete. Models saved in directory:", OUTPUT_DIR)
