import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns


def load_iat(filename):
    try:
        df = pd.read_csv(filename, header=None, names=["timestamp"])
        # Calculate diff and convert to seconds (keep as float)
        return df["timestamp"].diff().dropna()[1:]
    except:
        return []


def plot_comparison():
    # 1. Load Data
    real_iat = load_iat("real_traffic.csv")
    covert_iat = load_iat("covert_traffic.csv")

    if len(real_iat) == 0 or len(covert_iat) == 0:
        print("Error: Missing CSV data.")
        return

    # 2. Setup Plot (1 Row, 2 Columns)
    fig, axes = plt.subplots(1, 2, figsize=(16, 6), sharey=False)
    plt.style.use("seaborn-v0_8-whitegrid")

    # Common ticks and limits for consistent comparison
    x_ticks = [-3, -2, -1, 0, 1]
    x_tick_labels = ["1ms", "10ms", "100ms", "1s", "10s"]
    x_limit = (-3.5, 1)

    # --- Plot 1: Legitimate Traffic (Left Column) ---
    sns.kdeplot(
        np.log10(real_iat),
        fill=True,
        color="gray",
        alpha=0.5,
        ax=axes[0],
        label="Legitimate",
    )
    axes[0].set_title("Legitimate Traffic (Cloudflare)", fontsize=14)
    axes[0].set_xlabel("Log10(IAT in Seconds)", fontsize=12)
    axes[0].set_ylabel("Density", fontsize=12)
    axes[0].set_xticks(x_ticks)
    axes[0].set_xticklabels(x_tick_labels)
    axes[0].set_xlim(x_limit)
    axes[0].grid(True, which="both", ls="-", alpha=0.5)
    axes[0].legend()

    # --- Plot 2: Covert Traffic (Right Column) ---
    sns.kdeplot(
        np.log10(covert_iat),
        fill=True,
        color="red",
        alpha=0.5,
        ax=axes[1],
        label="QuiCC (Shaped)",
    )
    axes[1].set_title("QuiCC Covert Traffic (Shaped)", fontsize=14)
    axes[1].set_xlabel("Log10(IAT in Seconds)", fontsize=12)
    axes[1].set_ylabel("Density", fontsize=12)
    axes[1].set_xticks(x_ticks)
    axes[1].set_xticklabels(x_tick_labels)
    axes[1].set_xlim(x_limit)
    axes[1].grid(True, which="both", ls="-", alpha=0.5)
    axes[1].legend()

    # Main title
    plt.suptitle("Inter-Arrival Time (IAT) Distribution Analysis", fontsize=16)

    # 3. Save
    plt.tight_layout()
    plt.savefig("evaluation_log_iat.png", dpi=300)
    print("[+] Plot saved to evaluation_log_iat.png")


if __name__ == "__main__":
    plot_comparison()
