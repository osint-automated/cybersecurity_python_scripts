"""
This script analyzes a CSV file of ransomware attack data to determine the motivation behind each attack.
It uses a scoring system to rate each attack on a scale of 0-100 for financial gain, data theft, operational disruption, and opportunism.
The script also enriches the data with industry-specific information to help determine the motivation.
The results are saved to a new CSV file and a series of charts are generated to visualize the data.
"""
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
import os

# --------------------------
# User Input: CSV Path
# --------------------------
csv_path = input("Enter the path to the CSV file: ").strip()
if not os.path.isfile(csv_path):
    raise FileNotFoundError(f"{csv_path} not found!")

# Load CSV
df = pd.read_csv(csv_path)

# --------------------------
# Optional: Industry Enrichment
# --------------------------
sector_scores = {
    'Healthcare': 95,
    'Finance': 90,
    'Manufacturing': 85,
    'Education': 80,
    'Government': 100
}

df['sector_leverage'] = df['activity'].map(lambda x: sector_scores.get(x, 50))

# --------------------------
# Motivation Scoring Functions
# --------------------------
def financial_score(row):
    score = 50
    description = str(row.get('description','')).lower()
    revenue_info = str(row.get('extrainfos','')).lower()
    if any(k in description for k in ['database', 'customer', 'ssn', 'payment', 'financial']):
        score += 30
    if 'revenue' in revenue_info:
        score += 20
    return min(score, 100)

def data_theft_score(row):
    score = 0
    description = str(row.get('description','')).lower()
    screenshot = row.get('screenshot', '')
    keywords = ['database', 'ssn', 'medical', 'confidential', 'patient', 'records', 'pii']
    matches = sum([1 for k in keywords if k in description])
    score += matches * 20
    if screenshot and screenshot != '':
        score += 20
    return min(score, 100)

def operational_disruption_score(row):
    score = 0
    description = str(row.get('description','')).lower()
    critical_sectors = ['healthcare', 'manufacturing', 'government', 'logistics']
    if any(s in str(row.get('activity','')).lower() for s in critical_sectors):
        score += 40
    if any(k in description for k in ['disruption', 'shutdown', 'operations', 'downtime']):
        score += 40
    return min(score, 100)

def opportunistic_score(row):
    score = 0
    description = str(row.get('description','')).lower()
    extrainfo = str(row.get('extrainfos','')).lower()
    if any(k in description for k in ['low security', 'unpatched', 'weak']):
        score += 50
    if any(k in extrainfo for k in ['small', '0 employees']):
        score += 30
    return min(score, 100)

def sector_leverage_score(row):
    return row.get('sector_leverage',50)

# --------------------------
# Apply Scoring
# --------------------------
df['financial_score'] = df.apply(financial_score, axis=1)
df['data_theft_score'] = df.apply(data_theft_score, axis=1)
df['operational_disruption_score'] = df.apply(operational_disruption_score, axis=1)
df['opportunistic_score'] = df.apply(opportunistic_score, axis=1)
df['sector_leverage_score'] = df.apply(sector_leverage_score, axis=1)

# --------------------------
# Save Results CSV
# --------------------------
base_filename = os.path.splitext(os.path.basename(csv_path))[0]
output_csv = f"{base_filename}_motivation_scores.csv"
df.to_csv(output_csv, index=False)
print(f"\nMotivation scores saved to {output_csv}\n")

# --------------------------
# Console Summary
# --------------------------
total_attacks = len(df)
top_groups = df['group'].value_counts().head(5)
avg_scores = df[['financial_score','data_theft_score','operational_disruption_score','opportunistic_score','sector_leverage_score']].mean()
group_avg_scores = df.groupby('group')[['financial_score','data_theft_score','operational_disruption_score','opportunistic_score','sector_leverage_score']].mean()
top_group_by_financial = group_avg_scores['financial_score'].idxmax()
top_group_by_data_theft = group_avg_scores['data_theft_score'].idxmax()

print("==============================")
print("      RANSOMWARE MOTIVATION REPORT      ")
print("==============================")
print(f"Total Attacks Analyzed: {total_attacks}\n")

print("Top 5 Ransomware Groups by Number of Attacks:")
for g, count in top_groups.items():
    print(f"  {g}: {count} attacks")
print("")

print("Average Motivation Scores Across All Victims:")
for k,v in avg_scores.items():
    print(f"  {k.replace('_score','').replace('_',' ').title()}: {v:.2f}/100")
print("")

print("Ransomware Groups with Highest Motivation Scores:")
print(f"  Financial Gain: {top_group_by_financial}")
print(f"  Data Theft: {top_group_by_data_theft}")
most_common_motivation = avg_scores.idxmax().replace('_score','').replace('_',' ').title()
print(f"\nMost Common Motivation Overall: {most_common_motivation}\n")

# --------------------------
# Plot Functions
# --------------------------
def save_plot(fig, filename):
    fig.savefig(filename, bbox_inches='tight')
    plt.close(fig)

# Average Motivation by Group
group_scores = df.groupby('group')[['financial_score','data_theft_score','operational_disruption_score','opportunistic_score','sector_leverage_score']].mean()
fig1, ax1 = plt.subplots(figsize=(12,8))
group_scores.plot(kind='bar', stacked=False, ax=ax1)
ax1.set_title('Average Motivation Scores by Ransomware Group')
ax1.set_ylabel('Score (0-100)')
plt.xticks(rotation=45, ha='right')
save_plot(fig1, f"{base_filename}_group_motivation_scores.png")

# Motivation Distribution Boxplot
fig2, ax2 = plt.subplots(figsize=(10,6))
sns.boxplot(data=df[['financial_score','data_theft_score','operational_disruption_score','opportunistic_score','sector_leverage_score']], ax=ax2)
ax2.set_title('Motivation Score Distribution Across All Victims')
ax2.set_ylabel('Score (0-100)')
save_plot(fig2, f"{base_filename}_motivation_distribution.png")

# Top 10 Financial Victims
top_financial = df.nlargest(10,'financial_score')
fig3, ax3 = plt.subplots(figsize=(10,6))
sns.barplot(x='financial_score', y='victim', data=top_financial, ax=ax3)
ax3.set_title('Top 10 Victims by Financial Motivation')
ax3.set_xlabel('Financial Score')
save_plot(fig3, f"{base_filename}_top10_financial.png")

# Heatmap of Motivations by Group
fig4, ax4 = plt.subplots(figsize=(12,10))
sns.heatmap(group_scores, annot=True, fmt=".1f", cmap='coolwarm', ax=ax4)
ax4.set_title('Heatmap of Average Motivation Scores by Group')
save_plot(fig4, f"{base_filename}_group_motivation_heatmap.png")

print("All motivation graphs saved as images.")
