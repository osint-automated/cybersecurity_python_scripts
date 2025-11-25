import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import os

# ---------------------------------------------------------------------
# Helper: Save plot as image
# ---------------------------------------------------------------------
def save_plot(fig, out_dir, base_name, suffix):
    """
    fig: the figure object
    out_dir: directory to save in
    base_name: original file name without extension
    suffix: chart-specific label
    """
    filename = f"{base_name}_{suffix}.png"
    filepath = os.path.join(out_dir, filename)
    fig.savefig(filepath, dpi=300, bbox_inches="tight")
    plt.close(fig)


# ---------------------------------------------------------------------
# Load CSV with user input
# ---------------------------------------------------------------------
csv_path = input("Enter the path to the CSV file: ").strip()

if not os.path.isfile(csv_path):
    print("[!] File not found.")
    exit()

# Build output filename base
base_name = os.path.splitext(os.path.basename(csv_path))[0]
out_dir = os.path.dirname(csv_path)

df = pd.read_csv(csv_path)

# ---------------------------------------------------------------------
# Fix inconsistent casing
# ---------------------------------------------------------------------
if "country" in df.columns:
    df["country"] = df["country"].astype(str).str.upper()

# ---------------------------------------------------------------------
# Parse dates
# ---------------------------------------------------------------------
for col in ["attackdate", "discovered"]:
    if col in df.columns:
        df[col] = pd.to_datetime(df[col], errors="coerce")


# ---------------------------------------------------------------------
# Compute detection delay
# ---------------------------------------------------------------------
if "attackdate" in df.columns and "discovered" in df.columns:
    df["detection_delay_days"] = (df["discovered"] - df["attackdate"]).dt.total_seconds() / 86400


# ---------------------------------------------------------------------
# BASIC METRICS
# ---------------------------------------------------------------------
print("\n==============================")
print("   RANSOMWARE CTI STATISTICS  ")
print("==============================\n")

print(f"Total Attacks: {len(df)}\n")

# Attacks per group
if "group" in df.columns:
    print("Attacks by Group:")
    print(df["group"].value_counts())
    print()

# Attacks per country
if "country" in df.columns:
    print("Attacks by Country:")
    print(df["country"].value_counts())
    print()

# Attacks per industry
if "activity" in df.columns:
    print("Attacks by Industry:")
    print(df["activity"].value_counts())
    print()

# Detection delay stats
if "detection_delay_days" in df.columns:
    print("\nDetection Delay (days):")
    print(df["detection_delay_days"].describe())
    print()


# ---------------------------------------------------------------------
# TIMELINE ANALYSIS (MONTHLY)
# ---------------------------------------------------------------------
if "attackdate" in df.columns and "group" in df.columns:
    df["month"] = df["attackdate"].dt.to_period("M").astype(str)

    timeline = df.groupby(["group", "month"]).size().unstack(fill_value=0)
    print("\nGroup Timeline (monthly):")
    print(timeline)
    print()

    # Plot heatmap
    fig, ax = plt.subplots(figsize=(14, 10))
    sns.heatmap(timeline, cmap="mako", ax=ax)
    ax.set_title("Ransomware Group Timeline (Monthly)")
    save_plot(fig, out_dir, base_name, "group_timeline")


# ---------------------------------------------------------------------
# PLOTS (Saved as images)
# ---------------------------------------------------------------------

# 1. Group distribution bar chart
if "group" in df.columns:
    fig, ax = plt.subplots(figsize=(12, 6))
    df["group"].value_counts().plot(kind="bar", ax=ax)
    ax.set_title("Attack Count by Ransomware Group")
    ax.set_ylabel("Count")
    save_plot(fig, out_dir, base_name, "group_distribution")

# 2. Country distribution
if "country" in df.columns:
    fig, ax = plt.subplots(figsize=(10, 5))
    df["country"].value_counts().plot(kind="bar", ax=ax)
    ax.set_title("Attacks by Country")
    ax.set_ylabel("Count")
    save_plot(fig, out_dir, base_name, "country_distribution")

# 3. Industry distribution
if "activity" in df.columns:
    fig, ax = plt.subplots(figsize=(10, 5))
    df["activity"].value_counts().plot(kind="bar", ax=ax)
    ax.set_title("Attacks by Industry")
    ax.set_ylabel("Count")
    save_plot(fig, out_dir, base_name, "industry_distribution")

# 4. Detection delay distribution
if "detection_delay_days" in df.columns:
    fig, ax = plt.subplots(figsize=(10, 5))
    sns.histplot(df["detection_delay_days"].dropna(), bins=50, ax=ax)
    ax.set_title("Detection Delay Distribution (Days)")
    save_plot(fig, out_dir, base_name, "detection_delay_distribution")


print(f"\n[+] All graphs saved to: {out_dir}")
print("[+] Filenames start with:", base_name)
