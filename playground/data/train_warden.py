import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, confusion_matrix
from sklearn.model_selection import train_test_split


def extract_features(filename, label):
    try:
        df = pd.read_csv(filename, header=None, names=["timestamp"])
        iat = df["timestamp"].diff().dropna()
    except Exception:
        return []

    WINDOW_SIZE = 20
    features = []

    for i in range(0, len(iat) - WINDOW_SIZE, WINDOW_SIZE):
        window = iat.iloc[i : i + WINDOW_SIZE]

        mean_val = np.mean(window)
        std_val = np.std(window)

        f = {
            # --- Magnitude Features (Scale Dependent) ---
            "mean_iat": mean_val,
            "std_iat": std_val,
            "max_iat": np.max(window),
            "min_iat": np.min(window),
            "total_duration": np.sum(window),
            # --- Shape Features (Scale Invariant) ---
            # Coefficient of Variation (CV) measures "burstiness" regardless of speed.
            # If we match this, we match the "behavior".
            "coeff_var": std_val / (mean_val + 1e-9),
            "label": label,
        }
        features.append(f)

    return features


def run_experiment():
    print("[-] Loading data...")
    real_data = extract_features("real_traffic.csv", 0)
    covert_data = extract_features("covert_traffic.csv", 1)

    if len(real_data) == 0 or len(covert_data) == 0:
        print("Error: Missing CSV data.")
        return

    # Create DataFrame
    dataset = real_data + covert_data
    df = pd.DataFrame(dataset)

    # -------------------------------------------------------
    # Experiment 1: Standard Warden (Includes Speed/Magnitude)
    # -------------------------------------------------------
    print("\n=== Experiment 1: Standard Warden (Magnitude + Shape) ===")
    print("Hypothesis: ~100% Accuracy (Due to Time Dilation)")

    # Use all features
    X = df.drop(["label", "coeff_var"], axis=1)
    y = df["label"]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.3, random_state=42
    )
    clf = RandomForestClassifier(n_estimators=100, random_state=42)
    clf.fit(X_train, y_train)

    print(f"Accuracy: {accuracy_score(y_test, clf.predict(X_test)):.2%}")

    # -------------------------------------------------------
    # Experiment 2: Robust Warden (Shape Only)
    # -------------------------------------------------------
    print("\n=== Experiment 2: Scale-Invariant Warden (Shape Only) ===")
    print("Hypothesis: Accuracy drops significantly (Proves behavioral mimicry)")
    print("Feature used: Coefficient of Variation (CV = Std/Mean)")

    # Train ONLY on the Scale-Invariant feature
    X_shape = df[["coeff_var"]]
    y_shape = df["label"]

    X_train, X_test, y_train, y_test = train_test_split(
        X_shape, y_shape, test_size=0.3, random_state=42
    )
    clf_shape = RandomForestClassifier(n_estimators=100, random_state=42)
    clf_shape.fit(X_train, y_train)
    y_pred = clf_shape.predict(X_test)

    acc = accuracy_score(y_test, y_pred)
    print(f"Accuracy: {acc:.2%}")
    print("Confusion Matrix:")
    print(confusion_matrix(y_test, y_pred))

    if acc < 0.70:
        print(
            "\n[SUCCESS] The classifier struggles to distinguish the traffic based on shape alone."
        )
    else:
        print("\n[NOTE] The shape is still somewhat distinguishable.")


if __name__ == "__main__":
    run_experiment()
