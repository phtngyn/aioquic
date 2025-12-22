"""
networksetup -listallhardwareports
sudo tshark -i en0 -a duration:60 -f "udp port 443" -T fields -e frame.time_epoch -E separator=, > real_traffic.csv
sudo tshark -i lo0 -a duration:60 -f "udp port 4433" -T fields -e frame.time_epoch -E separator=, > covert_traffic.csv
"""

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns
from scipy import stats


def load_iat(filename):
    try:
        df = pd.read_csv(filename, header=None, names=["timestamp"])
        df["iat"] = df["timestamp"].diff()
        iat = df["iat"].dropna()
        return iat[iat > 0]
    except Exception as e:
        print(f"Error reading {filename}: {e}")
        return None


def analyze_and_compare(real_file, covert_file):
    print(f"Loading {real_file} and {covert_file}...")

    real_iat = load_iat(real_file)
    covert_iat = load_iat(covert_file)

    if real_iat is None or covert_iat is None:
        return

    # --- 1. Calculate Parameters (Your original logic) ---
    def get_params(data):
        log_data = np.log(data)
        return np.mean(log_data), np.std(log_data), np.min(data)

    mu_real, sigma_real, min_real = get_params(real_iat)
    mu_cov, sigma_cov, min_cov = get_params(covert_iat)

    print("\n" + "=" * 50)
    print(" PARAMETER COMPARISON")
    print("=" * 50)
    print(f"{'Metric':<15} | {'Real Traffic':<15} | {'Covert Traffic':<15}")
    print("-" * 50)
    print(f"{'Mu':<15} | {mu_real:<15.4f} | {mu_cov:<15.4f}")
    print(f"{'Sigma':<15} | {sigma_real:<15.4f} | {sigma_cov:<15.4f}")
    print(f"{'Min Interval':<15} | {min_real:<15.6f} | {min_cov:<15.6f}")
    print("-" * 50)

    # --- 2. Statistical Proof (KS Test) ---
    # We test if Covert IATs could have been drawn from the Real IAT distribution
    ks_stat, p_value = stats.ks_2samp(real_iat, covert_iat)

    print("\n" + "=" * 50)
    print(" STATISTICAL STEALTH PROOF (KS Test)")
    print("=" * 50)
    print(f"KS Statistic: {ks_stat:.4f} (Lower is better, 0.0 = identical)")
    print(f"P-Value:      {p_value:.4f}")

    if p_value > 0.05:
        print("RESULT: PASS. Distributions are statistically indistinguishable.")
    else:
        print("RESULT: FAIL. Distributions are significantly different.")

    # --- 3. Generate Plot for Paper ---
    plt.figure(figsize=(10, 6))
    sns.kdeplot(
        np.log(real_iat), label="Real Traffic (Cloudflare)", fill=True, alpha=0.3
    )
    sns.kdeplot(np.log(covert_iat), label="Covert Traffic (Ours)", fill=True, alpha=0.3)
    plt.xlabel("Log(Inter-Arrival Time)")
    plt.title("Traffic Fingerprint Comparison")
    plt.legend()
    plt.grid(True, alpha=0.3)
    plt.savefig("traffic_comparison.png")
    print("\n[+] Plot saved to 'traffic_comparison.png'")


if __name__ == "__main__":
    analyze_and_compare("real_traffic.csv", "covert_traffic.csv")
