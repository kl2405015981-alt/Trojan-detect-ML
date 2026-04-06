"""
test_model.py - ML Model Evaluation Script
==========================================
Purpose: Evaluate the trained Trojan detection model's performance
         to achieve Project Objective 3.

Usage:
    python test_model.py

Requirements:
    - classifier.pkl (trained model)
    - test_dataset.csv (PE features with 'label' column: 0=Safe, 1=Trojan)
    
Output:
    - Accuracy, Precision, Recall, F1-Score
    - Confusion Matrix
    - Classification Report
    - test_results.txt (saved report)
"""

import os
import sys
import joblib
import pandas as pd
import numpy as np
from datetime import datetime
from sklearn.metrics import (
    accuracy_score, 
    precision_score, 
    recall_score, 
    f1_score,
    confusion_matrix, 
    classification_report
)

# ═══════════════════════════════════════════════════════════════
# CONFIGURATION
# ═══════════════════════════════════════════════════════════════

MODEL_PATH = 'classifier.pkl'
TEST_DATA_PATH = 'test_dataset.csv'
RESULTS_FILE = 'test_results.txt'

# Expected features (must match training)
FEATURE_COLUMNS = [
    'Machine', 'SizeOfOptionalHeader', 'Characteristics',
    'MajorLinkerVersion', 'SizeOfCode', 'SizeOfInitializedData',
    'SizeOfUninitializedData', 'AddressOfEntryPoint', 'BaseOfCode',
    'ImageBase', 'SectionAlignment', 'FileAlignment',
    'MajorOperatingSystemVersion', 'SizeOfImage', 'SizeOfHeaders',
    'CheckSum', 'Subsystem', 'DllCharacteristics',
    'SizeOfStackReserve', 'SizeOfHeapReserve', 'LoaderFlags',
    'NumberOfRvaAndSizes', 'SectionsMaxEntropy'
]


# ═══════════════════════════════════════════════════════════════
# FUNCTIONS
# ═══════════════════════════════════════════════════════════════

def print_header(text):
    """Print formatted section header"""
    print("\n" + "="*60)
    print(f"  {text}")
    print("="*60)


def load_model():
    """Load the trained classifier"""
    if not os.path.exists(MODEL_PATH):
        print(f"❌ Error: Model file '{MODEL_PATH}' not found!")
        print(f"   Please ensure you have trained the model first.")
        sys.exit(1)
    
    print(f"✓ Loading model from {MODEL_PATH}...")
    model = joblib.load(MODEL_PATH)
    print(f"  Model type: {type(model).__name__}")
    return model


def load_test_data():
    """Load and validate test dataset"""
    if not os.path.exists(TEST_DATA_PATH):
        print(f"❌ Error: Test data file '{TEST_DATA_PATH}' not found!")
        print(f"   Please provide a CSV file with PE features and 'label' column.")
        print(f"   Format: {', '.join(FEATURE_COLUMNS)}, label")
        sys.exit(1)
    
    print(f"✓ Loading test data from {TEST_DATA_PATH}...")
    df = pd.read_csv(TEST_DATA_PATH)
    
    # Validate label column
    if 'label' not in df.columns:
        print(f"❌ Error: 'label' column not found in test dataset!")
        print(f"   Available columns: {list(df.columns)}")
        sys.exit(1)
    
    # Validate feature columns
    missing_cols = [col for col in FEATURE_COLUMNS if col not in df.columns]
    if missing_cols:
        print(f"❌ Error: Missing required feature columns:")
        for col in missing_cols:
            print(f"   - {col}")
        sys.exit(1)
    
    # Separate features and labels
    X_test = df[FEATURE_COLUMNS]
    y_test = df['label']
    
    print(f"  Total samples: {len(df)}")
    print(f"  Safe files (0): {(y_test == 0).sum()}")
    print(f"  Trojan files (1): {(y_test == 1).sum()}")
    
    return X_test, y_test


def evaluate_model(model, X_test, y_test):
    """Perform comprehensive model evaluation"""
    print_header("MAKING PREDICTIONS")
    
    # Predict
    print("Running predictions on test set...")
    y_pred = model.predict(X_test)
    y_prob = model.predict_proba(X_test)[:, 1]  # Probability of Trojan class
    
    # Calculate metrics
    print_header("PERFORMANCE METRICS")
    
    accuracy  = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred, zero_division=0)
    recall    = recall_score(y_test, y_pred, zero_division=0)
    f1        = f1_score(y_test, y_pred, zero_division=0)
    
    print(f"Accuracy:  {accuracy * 100:.2f}%")
    print(f"Precision: {precision * 100:.2f}%")
    print(f"Recall:    {recall * 100:.2f}%")
    print(f"F1-Score:  {f1 * 100:.2f}%")
    
    # Confusion Matrix
    print_header("CONFUSION MATRIX")
    cm = confusion_matrix(y_test, y_pred)
    
    tn, fp, fn, tp = cm.ravel()
    
    print("\n           Predicted")
    print("            Safe  Trojan")
    print(f"Actual Safe   {tn:4d}   {fp:4d}")
    print(f"      Trojan  {fn:4d}   {tp:4d}")
    
    print(f"\n• True Negatives (TN):  {tn} — Safe files correctly identified")
    print(f"• False Positives (FP): {fp} — Safe files wrongly marked as Trojan")
    print(f"• False Negatives (FN): {fn} — Trojan files missed")
    print(f"• True Positives (TP):  {tp} — Trojan files correctly detected")
    
    # Additional metrics
    print_header("DETECTION RATES")
    
    tpr = tp / (tp + fn) if (tp + fn) > 0 else 0  # True Positive Rate (Recall)
    tnr = tn / (tn + fp) if (tn + fp) > 0 else 0  # True Negative Rate
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0  # False Positive Rate
    fnr = fn / (fn + tp) if (fn + tp) > 0 else 0  # False Negative Rate
    
    print(f"True Positive Rate (TPR):   {tpr * 100:.2f}% — Trojan detection rate")
    print(f"True Negative Rate (TNR):   {tnr * 100:.2f}% — Safe file accuracy")
    print(f"False Positive Rate (FPR):  {fpr * 100:.2f}% — Safe files misclassified")
    print(f"False Negative Rate (FNR):  {fnr * 100:.2f}% — Missed Trojans")
    
    # Classification Report
    print_header("DETAILED CLASSIFICATION REPORT")
    print(classification_report(y_test, y_pred, target_names=['Safe', 'Trojan']))
    
    return {
        'accuracy': accuracy,
        'precision': precision,
        'recall': recall,
        'f1_score': f1,
        'confusion_matrix': cm,
        'tpr': tpr,
        'tnr': tnr,
        'fpr': fpr,
        'fnr': fnr,
        'y_test': y_test,
        'y_pred': y_pred,
        'y_prob': y_prob
    }


def save_results(results, model):
    """Save evaluation results to file"""
    print_header("SAVING RESULTS")
    
    with open(RESULTS_FILE, 'w', encoding='utf-8') as f:
        f.write("="*60 + "\n")
        f.write("  TROJAN DETECTION MODEL - EVALUATION RESULTS\n")
        f.write("="*60 + "\n")
        f.write(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Model: {type(model).__name__}\n")
        f.write(f"Test samples: {len(results['y_test'])}\n\n")
        
        f.write("PERFORMANCE METRICS\n")
        f.write("-"*60 + "\n")
        f.write(f"Accuracy:  {results['accuracy'] * 100:.2f}%\n")
        f.write(f"Precision: {results['precision'] * 100:.2f}%\n")
        f.write(f"Recall:    {results['recall'] * 100:.2f}%\n")
        f.write(f"F1-Score:  {results['f1_score'] * 100:.2f}%\n\n")
        
        f.write("CONFUSION MATRIX\n")
        f.write("-"*60 + "\n")
        cm = results['confusion_matrix']
        tn, fp, fn, tp = cm.ravel()
        f.write(f"True Negatives (TN):  {tn}\n")
        f.write(f"False Positives (FP): {fp}\n")
        f.write(f"False Negatives (FN): {fn}\n")
        f.write(f"True Positives (TP):  {tp}\n\n")
        
        f.write("DETECTION RATES\n")
        f.write("-"*60 + "\n")
        f.write(f"TPR (Trojan Detection): {results['tpr'] * 100:.2f}%\n")
        f.write(f"TNR (Safe Accuracy):    {results['tnr'] * 100:.2f}%\n")
        f.write(f"FPR (False Alarms):     {results['fpr'] * 100:.2f}%\n")
        f.write(f"FNR (Missed Trojans):   {results['fnr'] * 100:.2f}%\n\n")
        
        f.write("INTERPRETATION\n")
        f.write("-"*60 + "\n")
        
        # Objective achievement check
        if results['accuracy'] >= 0.85:
            f.write("✓ OBJECTIVE 3 ACHIEVED: Accuracy ≥ 85%\n")
        else:
            f.write("OBJECTIVE 3 NOT MET: Accuracy < 85%\n")
        
        if results['recall'] >= 0.80:
            f.write("✓ Good Trojan detection rate (Recall ≥ 80%)\n")
        else:
            f.write("⚠ Low Trojan detection rate (Recall < 80%)\n")
        
        if results['fpr'] <= 0.10:
            f.write("✓ Low false alarm rate (FPR ≤ 10%)\n")
        else:
            f.write("⚠ High false alarm rate (FPR > 10%)\n")
    
    print(f"✓ Results saved to {RESULTS_FILE}")


def interpret_results(results):
    """Provide interpretation and recommendations"""
    print_header("INTERPRETATION & RECOMMENDATIONS")
    
    # Check objectives
    if results['accuracy'] >= 0.85:
        print("✅ OBJECTIVE 3 ACHIEVED!")
        print("   Model accuracy meets the ≥85% target for FYP.")
    else:
        print("⚠️  OBJECTIVE 3 NOT FULLY MET")
        print(f"   Current accuracy: {results['accuracy']*100:.2f}%")
        print("   Target: ≥85%")
        print("   → Consider retraining with more data or different features")
    
    # Trojan detection
    if results['recall'] >= 0.80:
        print(f"\n✅ Good Trojan Detection: {results['recall']*100:.2f}%")
        print("   Model successfully catches most Trojan files.")
    else:
        print(f"\n⚠️  Weak Trojan Detection: {results['recall']*100:.2f}%")
        print("   → Model misses too many Trojan files")
        print("   → Increase training samples of Trojan class")
    
    # False positives
    if results['fpr'] <= 0.10:
        print(f"\n✅ Low False Alarms: {results['fpr']*100:.2f}%")
        print("   Model rarely misclassifies safe files.")
    else:
        print(f"\n⚠️  High False Alarms: {results['fpr']*100:.2f}%")
        print("   → Too many safe files marked as Trojan")
        print("   → Adjust decision threshold or retrain")
    
    print("\n" + "="*60)


# ═══════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════

def main():
    print("\n" + "="*60)
    print("  TROJAN DETECTION MODEL - EVALUATION SCRIPT")
    print("  FYP: Machine Learning-Based Trojan Horse Detection")
    print("="*60)
    
    # Step 1: Load model
    model = load_model()
    
    # Step 2: Load test data
    X_test, y_test = load_test_data()
    
    # Step 3: Evaluate
    results = evaluate_model(model, X_test, y_test)
    
    # Step 4: Interpret
    interpret_results(results)
    
    # Step 5: Save results
    save_results(results, model)
    
    print("\n✓ Evaluation complete!")
    print(f"  Results saved to: {RESULTS_FILE}\n")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠ Evaluation cancelled by user.")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Error: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)