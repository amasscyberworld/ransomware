
import pandas as pd
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report

def train_model(csv_file="model/ransomware_dataset.csv", model_file="model/ransomware_model.pkl"):
    print("[*] Loading dataset...")
    df = pd.read_csv(csv_file)

    # Encode categorical 'extension'
    le = LabelEncoder()
    df['extension'] = le.fit_transform(df['extension'])

    X = df[['entropy', 'size_kb', 'extension']]
    y = df['label']

    # Encode labels
    y = LabelEncoder().fit_transform(y)

    # Split and train
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    print("[*] Training Random Forest...")
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train, y_train)

    print("[✓] Training complete.")
    y_pred = model.predict(X_test)
    print(classification_report(y_test, y_pred))

    print(f"[*] Saving model as: {model_file}")
    joblib.dump(model, model_file)
    print("[✓] Model saved.")

if __name__ == "__main__":
    train_model()
