import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier


# ============================================================
# STEP 1: LOAD DATASET
# ============================================================

df = pd.read_csv("data/security_logs.csv")

print("\n===== DATASET LOADED SUCCESSFULLY =====")
print("Shape:", df.shape)


# ============================================================
# STEP 2: CLEAN COLUMN NAMES
# ============================================================

df.columns = df.columns.str.strip()

print("\n===== CLEANED COLUMN NAMES =====")
print(df.columns.tolist())


# ============================================================
# STEP 3: CHECK TRAFFIC LABELS
# ============================================================

print("\n===== TRAFFIC LABEL DISTRIBUTION =====")
print(df["Label"].value_counts())

print("\n===== UNIQUE LABELS =====")
print(df["Label"].unique())


# ============================================================
# STEP 4: SEPARATE FEATURES AND TARGET
# ============================================================

X = df.drop("Label", axis=1)
y = df["Label"]


# ============================================================
# STEP 5: CONVERT FEATURES TO NUMERIC
# ============================================================

print("\n===== CONVERTING FEATURES TO NUMERIC =====")

for column in X.columns:
    X[column] = pd.to_numeric(X[column], errors="coerce")


# ============================================================
# STEP 6: HANDLE INFINITY VALUES
# ============================================================

print("\n===== CHECKING INFINITE VALUES =====")

infinite_count = X.isin([float("inf"), float("-inf")]).sum().sum()

print("Infinite values before cleaning:", infinite_count)

# Convert infinity and negative infinity to NaN
X = X.replace([float("inf"), float("-inf")], float("nan"))


# ============================================================
# STEP 7: HANDLE MISSING VALUES
# ============================================================

missing_before = X.isnull().sum().sum()

print("Missing values before cleaning:", missing_before)

# Replace missing values with median of each feature
for column in X.columns:

    median_value = X[column].median()

    X[column] = X[column].fillna(median_value)


# ============================================================
# STEP 8: FINAL DATA CLEANING CHECK
# ============================================================

print("\n===== FINAL DATA CLEANING CHECK =====")

print("Total missing values:", X.isnull().sum().sum())

print(
    "Total infinite values:",
    X.isin([float("inf"), float("-inf")]).sum().sum()
)

print("\nFeature data types:")
print(X.dtypes.value_counts())


# ============================================================
# STEP 9: FEATURES AND TARGET INFORMATION
# ============================================================

print("\n===== FEATURES AND TARGET =====")

print("X shape:", X.shape)
print("y shape:", y.shape)

print("\nTarget classes:")
print(y.value_counts())


# ============================================================
# STEP 10: TRAIN / TEST SPLIT
# ============================================================

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y
)

print("\n===== TRAIN TEST SPLIT =====")

print("Training features:", X_train.shape)
print("Testing features:", X_test.shape)

print("Training labels:", y_train.shape)
print("Testing labels:", y_test.shape)


# ============================================================
# STEP 11: CREATE THREAT DETECTION MODEL
# ============================================================

model = RandomForestClassifier(
    n_estimators=100,
    random_state=42,
    n_jobs=-1
)

print("\n===== TRAINING THREAT DETECTION MODEL =====")


# ============================================================
# STEP 12: TRAIN MODEL
# ============================================================

model.fit(X_train, y_train)

print("Model training completed!")

# ============================================================
# STEP 16: MODEL EVALUATION
# ============================================================

from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix
)

print("\n===== MODEL PREDICTION =====")

# Make predictions on unseen test data
y_pred = model.predict(X_test)

print("Prediction completed!")


# ============================================================
# ACCURACY
# ============================================================

accuracy = accuracy_score(y_test, y_pred)

print("\n===== MODEL ACCURACY =====")
print(f"Accuracy: {accuracy:.4f}")
print(f"Accuracy Percentage: {accuracy * 100:.2f}%")


# ============================================================
# CLASSIFICATION REPORT
# ============================================================

print("\n===== CLASSIFICATION REPORT =====")

print(classification_report(y_test, y_pred))


# ============================================================
# CONFUSION MATRIX
# ============================================================

print("\n===== CONFUSION MATRIX =====")

cm = confusion_matrix(
    y_test,
    y_pred,
    labels=["BENIGN", "DDoS"]
)

print(cm)

# ============================================================
# STEP 17: SAVE TRAINED MODEL
# ============================================================

import joblib

# Save the trained model
joblib.dump(model, "models/threat_detection_model.pkl")

print("\n===== MODEL SAVED =====")
print("Model saved to: models/threat_detection_model.pkl")