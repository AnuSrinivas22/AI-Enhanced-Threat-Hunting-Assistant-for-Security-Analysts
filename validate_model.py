import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split


# ============================================================
# LOAD DATASET
# ============================================================

df = pd.read_csv("data/security_logs.csv")

# Clean column names
df.columns = df.columns.str.strip()


# ============================================================
# SEPARATE FEATURES AND TARGET
# ============================================================

X = df.drop("Label", axis=1)
y = df["Label"]


# ============================================================
# CONVERT FEATURES TO NUMERIC
# ============================================================

for column in X.columns:
    X[column] = pd.to_numeric(X[column], errors="coerce")


# ============================================================
# HANDLE INFINITY AND MISSING VALUES
# ============================================================

X = X.replace([np.inf, -np.inf], np.nan)

for column in X.columns:
    X[column] = X[column].fillna(X[column].median())


# ============================================================
# REMOVE EXACT DUPLICATE FLOWS
# ============================================================

print("\n===== BEFORE DUPLICATE REMOVAL =====")
print("Total rows:", len(X))

duplicate_count = X.duplicated().sum()

print("Duplicate rows:", duplicate_count)

# Keep the first occurrence of each identical feature row
unique_indices = ~X.duplicated()

X = X.loc[unique_indices].reset_index(drop=True)
y = y.loc[unique_indices].reset_index(drop=True)


print("\n===== AFTER DUPLICATE REMOVAL =====")
print("Total rows:", len(X))
print("Removed rows:", duplicate_count)
print("Remaining duplicates:", X.duplicated().sum())


# ============================================================
# TRAIN / TEST SPLIT
# ============================================================

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y
)


# ============================================================
# CHECK TRAIN / TEST OVERLAP
# ============================================================

print("\n===== TRAIN / TEST OVERLAP CHECK =====")

train_rows = set(map(tuple, X_train.values))
test_rows = set(map(tuple, X_test.values))

overlap = train_rows.intersection(test_rows)

print("Exact overlapping rows:", len(overlap))

if len(overlap) == 0:
    print("No exact feature overlap detected.")
else:
    print("Warning: overlapping feature rows detected.")


# ============================================================
# LABEL DISTRIBUTION
# ============================================================

print("\n===== TRAINING LABEL DISTRIBUTION =====")
print(y_train.value_counts())

print("\n===== TESTING LABEL DISTRIBUTION =====")
print(y_test.value_counts())


# ============================================================
# FINAL SHAPES
# ============================================================

print("\n===== FINAL DATASET SHAPES =====")

print("X:", X.shape)
print("X_train:", X_train.shape)
print("X_test:", X_test.shape)

print("y:", y.shape)
print("y_train:", y_train.shape)
print("y_test:", y_test.shape)

# ============================================================
# STEP 20: TRAIN VALIDATED THREAT DETECTION MODEL
# ============================================================

from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix
)
import joblib


print("\n===== TRAINING VALIDATED THREAT DETECTION MODEL =====")

# Create Random Forest model
validated_model = RandomForestClassifier(
    n_estimators=100,
    random_state=42,
    n_jobs=-1
)

# Train using duplicate-free training data
validated_model.fit(X_train, y_train)

print("Validated model training completed!")


# ============================================================
# MAKE PREDICTIONS
# ============================================================

print("\n===== VALIDATED MODEL PREDICTION =====")

y_pred = validated_model.predict(X_test)

print("Prediction completed!")


# ============================================================
# ACCURACY
# ============================================================

accuracy = accuracy_score(y_test, y_pred)

print("\n===== VALIDATED MODEL ACCURACY =====")

print(f"Accuracy: {accuracy:.4f}")
print(f"Accuracy Percentage: {accuracy * 100:.2f}%")


# ============================================================
# CLASSIFICATION REPORT
# ============================================================

print("\n===== VALIDATED CLASSIFICATION REPORT =====")

print(
    classification_report(
        y_test,
        y_pred
    )
)


# ============================================================
# CONFUSION MATRIX
# ============================================================

print("\n===== VALIDATED CONFUSION MATRIX =====")

cm = confusion_matrix(
    y_test,
    y_pred,
    labels=["BENIGN", "DDoS"]
)

print(cm)


# ============================================================
# SAVE VALIDATED MODEL
# ============================================================

joblib.dump(
    validated_model,
    "models/threat_detection_model_validated.pkl"
)

print("\n===== VALIDATED MODEL SAVED =====")

print(
    "Model saved to: "
    "models/threat_detection_model_validated.pkl"
)