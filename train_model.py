import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, confusion_matrix, precision_score, recall_score, f1_score
import joblib
import os
import sqlite3
from datetime import datetime

# train_model.py - FULL VERSION (Accuracy + Confusion Matrix)
# Ensures training date and matrix data are saved for Dashboard display

def train():
    dataset_file = 'malware_dataset.csv'
    db_file = 'database.sqlite'
    results_file = 'test_results.txt'

    if not os.path.exists(dataset_file):
        print(f"ERROR: File '{dataset_file}' not found!")
        return

    print("Starting to process dataset (5,000 records)...")
    try:
        data = pd.read_csv(dataset_file)
    except Exception as e:
        print(f"ERROR: CSV Failed: {str(e)}")
        return
    
    X = data.drop(['Name', 'md5', 'legitimate'], axis=1)
    y = data['legitimate']

    # Split data (80% Training, 20% Testing)
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2)

    print("Training Random Forest model...")
    clf = RandomForestClassifier(n_estimators=100)
    clf.fit(X_train, y_train)

    # --- PERFORMANCE METRICS CALCULATION ---
    y_pred = clf.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred)
    rec = recall_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)
    
    # Confusion Matrix: [TN, FP], [FN, TP]
    tn, fp, fn, tp = confusion_matrix(y_test, y_pred).ravel()
    
    accuracy_percentage = round(acc * 100, 2)
    
    # Save model .pkl
    joblib.dump(clf, 'classifier.pkl')
    print(f"SUCCESS: ACCURACY: {accuracy_percentage}%")

    # --- GENERATE test_results.txt FILE FOR DASHBOARD ---
    # This file is used by PHP to build the Confusion Matrix table
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(results_file, 'w') as f:
        f.write(f"Timestamp: {now_str}\n")
        f.write(f"Precision: {prec*100:.2f}%\n")
        f.write(f"Recall: {rec*100:.2f}%\n")
        f.write(f"F1-Score: {f1*100:.2f}%\n")
        f.write(f"True Negatives (TN): {tn}\n")
        f.write(f"False Positives (FP): {fp}\n")
        f.write(f"False Negatives (FN): {fn}\n")
        f.write(f"True Positives (TP): {tp}\n")
    print(f"SUCCESS: File '{results_file}' has been updated.")

    # --- DATABASE INTEGRATION (TO DISPLAY TRAINING DATE) ---
    try:
        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()
        
        # Ensure created_at column exists
        try:
            cursor.execute("ALTER TABLE ml_models ADD COLUMN created_at DATETIME")
        except:
            pass 

        cursor.execute("UPDATE ml_models SET is_active = 0")
        
        now_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        model_display = f"TrojanDetector v2.5 (Updated {datetime.now().strftime('%H:%M:%S')})"
        
        cursor.execute("""
            INSERT INTO ml_models (model_name, algorithm, accuracy, is_active, created_at)
            VALUES (?, ?, ?, ?, ?)
        """, (model_display, 'Random Forest', accuracy_percentage, 1, now_time))
        
        conn.commit()
        conn.close()
        print(f"DATABASE: Training record has been saved!")
            
    except Exception as e:
        print(f"DATABASE ERROR: {str(e)}")

if __name__ == "__main__":
    train()