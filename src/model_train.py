import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
from sklearn.utils import resample
import joblib
from src.feature_extraction import extract_basic_features

# --------------------------
# Load dataset
# --------------------------
df = pd.read_csv("data/raw/phishtank_dataset.csv")

# Rename 'type' → 'label'
df = df.rename(columns={'type': 'label'})[['url', 'label']]
df = df[df['url'].notna()]

# Check class distribution (after rename)
print("Class distribution:\n", df['label'].value_counts())

# --------------------------
# Convert labels to binary
# --------------------------
def label_to_binary(lbl):
    lbl = lbl.lower()
    if lbl in ['benign', 'legitimate', 'good']:
        return 0
    else:
        return 1

df['label'] = df['label'].apply(label_to_binary)

# --------------------------
# Feature extraction
# --------------------------
feature_data = []
for _, row in df.iterrows():
    feats = extract_basic_features(row['url'])
    feats['label'] = row['label']
    feature_data.append(feats)

final_df = pd.DataFrame(feature_data)
final_df.to_csv("data/processed/final_dataset.csv", index=False)

# --------------------------
# Handle class imbalance
# --------------------------
majority = final_df[final_df.label == 0]
minority = final_df[final_df.label == 1]

minority_upsampled = resample(minority,
                              replace=True,
                              n_samples=len(majority),
                              random_state=42)
balanced_df = pd.concat([majority, minority_upsampled])

# --------------------------
# Train/test split
# --------------------------
X = balanced_df.drop(columns=['label', 'domain'])
y = balanced_df['label']

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# --------------------------
# Train Random Forest
# --------------------------
model = RandomForestClassifier(n_estimators=300, random_state=42)
model.fit(X_train, y_train)

print("\nModel Evaluation:\n")
print(classification_report(y_test, model.predict(X_test)))

# --------------------------
# Save model
# --------------------------
joblib.dump(model, "phishguard_model.pkl")
print("\n✅ Model saved as 'phishguard_model.pkl'")
