"""
networksetup -listallhardwareports
sudo tshark -i eth0 -f "udp port 443" -T fields -e frame.time_epoch -E separator=, > youtube_traffic.csv
"""

import numpy as np
import pandas as pd


def calculate_shaping_params(filename):
    """
    Analyzes packet timestamps to derive TrafficShaper parameters (Log-Normal distribution).
    """
    print(f"Analyzing {filename}...")

    # Step 1: Load Data
    # Read the raw packet timestamps captured via Wireshark/TShark
    try:
        df = pd.read_csv(filename, header=None, names=["timestamp"])
    except Exception as e:
        print(f"Error reading file: {e}")
        return

    # Step 2: Calculate Inter-Arrival Times (IAT)
    # Compute the delta between consecutive packets (Time_n - Time_n-1)
    df["iat"] = df["timestamp"].diff()

    # Data Cleaning:
    # - Drop NaN (first packet has no previous packet)
    # - Drop zeros (bursts sent instantly) to avoid log(0) errors
    iat_data = df["iat"].dropna()
    iat_data = iat_data[iat_data > 0]

    if len(iat_data) < 10:
        print("Error: Insufficient data points (<10). Check capture.")
        return

    # Step 3: Fit to Log-Normal Distribution
    # Log-Normal is defined by the Mean (mu) and StdDev (sigma) of the *logarithm* of the data.
    # We take natural log of IATs, then calculate standard normal statistics.
    log_data = np.log(iat_data)
    mu = np.mean(log_data)
    sigma = np.std(log_data)

    # Step 4: Determine Minimum Interval ("Speed Limit")
    # Identify the fastest packet gap to prevent unrealistic machine-gunning.
    min_interval = np.min(iat_data)

    # Output Results
    print("-" * 40)
    print("TRAFFIC SHAPING PARAMETERS")
    print("-" * 40)
    print(f"Total Packets:    {len(iat_data)}")
    print(f"Average IAT:      {np.mean(iat_data):.6f} seconds")
    print("-" * 40)
    print("Use these values in your TrafficShaper class:")
    print(f"self.mu = {mu:.4f}")
    print(f"self.sigma = {sigma:.4f}")
    print(f"self.min_interval = {min_interval:.6f}")
    print("-" * 40)


if __name__ == "__main__":
    calculate_shaping_params("./youtube_traffic.csv")

"""
========================================
REFERENCE RESULTS (YouTube 4K Stream)
========================================
Total Packets Analyzed: 44,032
Average IAT:            0.001328 seconds

Recommended TrafficShaper Configuration:
----------------------------------------
self.mu = -11.8349
self.sigma = 2.5097
self.min_interval = 0.000001
========================================
"""
