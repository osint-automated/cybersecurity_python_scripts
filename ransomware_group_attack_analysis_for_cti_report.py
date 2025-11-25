import pandas as pd
import matplotlib.pyplot as plt
import os

# -----------------------
# 1. Load CSV from ransomware_live_victim_search_by_group.py output
# -----------------------
csv_path = input("Enter the path to the CSV file: ").strip()

try:
    df = pd.read_csv(csv_path)
except FileNotFoundError:
    print(f"[!] File not found: {csv_path}")
    exit(1)

# Normalize column names
df.columns = df.columns.str.lower().str.replace(" ", "_")

# -----------------------
# 2. Convert date columns to datetime
# -----------------------
df["attackdate"] = pd.to_datetime(df["attackdate"], errors="coerce")
df["discovered"] = pd.to_datetime(df["discovered"], errors="coerce")
df = df.dropna(subset=["attackdate", "discovered"])

# -----------------------
# 3. Add time buckets
# -----------------------
df["year"] = df["attackdate"].dt.year
df["month"] = df["attackdate"].dt.to_period("M")
df["week"] = df["attackdate"].dt.to_period("W")
df["quarter"] = df["attackdate"].dt.to_period("Q")

# Compute detection/leak delay (days)
df["detection_delay_days"] = (df["discovered"] - df["attackdate"]).dt.total_seconds() / 86400

# Replace missing or unknown industry with 'Unknown'
df["activity"] = df["activity"].replace("Not Found", "Unknown")

# -----------------------
# 4. Compute basic CTI statistics
# -----------------------
total_attacks = len(df)
attacks_by_group = df["group"].value_counts()
attacks_by_country = df["country"].value_counts()
attacks_by_industry = df["activity"].value_counts()
attacks_over_time = df.groupby("month").size()
delay_stats = df["detection_delay_days"].describe()
group_timeline = df.groupby(["group", "month"]).size().unstack(fill_value=0)

# -----------------------
# 5. Print summary
# -----------------------
print("\n===========================")
print(" CTI Ransomware Statistics")
print("===========================\n")
print(f"Total attacks: {total_attacks}")
print("\nTop ransomware groups:\n", attacks_by_group)
print("\nTop victim countries:\n", attacks_by_country)
print("\nTop industries targeted:\n", attacks_by_industry)
print("\nLeak detection delay statistics (days):\n", delay_stats)
print("\nGroup timeline (attacks per month):\n", group_timeline)

# -----------------------
# 6. Create output folder for images
# -----------------------
output_folder = "ransomware_charts"
os.makedirs(output_folder, exist_ok=True)

# -----------------------
# 7. Visualizations + Save Images
# -----------------------

# 7a. Attacks over time
plt.figure(figsize=(12,5))
attacks_over_time.plot(marker="o")
plt.title("Ransomware Attacks Over Time")
plt.xlabel("Month")
plt.ylabel("Number of Attacks")
plt.grid(True)
plt.tight_layout()
plt.savefig(os.path.join(output_folder, "attacks_over_time.png"))
plt.close()

# 7b. Industry distribution
plt.figure(figsize=(10,4))
attacks_by_industry.plot(kind="bar", color="skyblue")
plt.title("Industry Targeting Distribution")
plt.ylabel("Victim Count")
plt.tight_layout()
plt.savefig(os.path.join(output_folder, "industry_distribution.png"))
plt.close()

# 7c. Country distribution
plt.figure(figsize=(10,4))
attacks_by_country.plot(kind="bar", color="salmon")
plt.title("Victims by Country")
plt.ylabel("Victim Count")
plt.tight_layout()
plt.savefig(os.path.join(output_folder, "country_distribution.png"))
plt.close()

# 7d. Ransomware group activity
plt.figure(figsize=(10,4))
attacks_by_group.plot(kind="bar", color="lightgreen")
plt.title("Ransomware Group Activity")
plt.ylabel("Number of Attacks")
plt.tight_layout()
plt.savefig(os.path.join(output_folder, "group_activity.png"))
plt.close()

# 7e. Leak detection delay histogram
plt.figure(figsize=(10,4))
df["detection_delay_days"].plot(kind="hist", bins=10, color="orange")
plt.title("Leak Detection Delay Distribution")
plt.xlabel("Delay (days)")
plt.tight_layout()
plt.savefig(os.path.join(output_folder, "leak_detection_delay.png"))
plt.close()

print(f"\n[+] All charts saved in the folder '{output_folder}'")
