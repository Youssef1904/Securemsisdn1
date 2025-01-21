# Reimporting necessary libraries due to session reset
import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
from datetime import timedelta

# Recreating project phases with updated durations for the Gantt chart
tasks = {
    'Phase': [
        'Project Planning',
        'Requirement Gathering',
        'System Design',
        'Development (Encryption/Decryption)',
        'Cloud Interaction Setup (Simulation)',
        'Testing and Debugging',
        'UI/UX Design',
        'Final Integration and Review',
        'Documentation',
        'Final Review and Submission'
    ],
    'Start Date': [
        '2024-10-01', '2024-11-01', '2024-11-15', '2024-12-01', '2025-01-01',
        '2025-02-01', '2025-02-15', '2025-03-01', '2025-03-15', '2025-04-01'
    ],
    'Duration (days)': [30, 15, 15, 30, 30, 15, 15, 15, 10, 5]
}

# Convert to DataFrame
df = pd.DataFrame(tasks)

# Calculate end dates based on start date and duration
df['Start Date'] = pd.to_datetime(df['Start Date'])
df['End Date'] = df['Start Date'] + pd.to_timedelta(df['Duration (days)'], unit='d')

# Plotting the Gantt chart
fig, ax = plt.subplots(figsize=(14, 8))
for i, task in df.iterrows():
    ax.barh(task['Phase'], (task['End Date'] - task['Start Date']).days, left=task['Start Date'], color='lightsteelblue')
    ax.text(task['Start Date'] + timedelta(days=task['Duration (days)']//2), i, f"{task['Duration (days)']} days", 
            va='center', ha='center', color='black')

# Formatting for 6-month timeline
ax.xaxis.set_major_locator(mdates.MonthLocator(interval=1))
ax.xaxis.set_major_formatter(mdates.DateFormatter('%Y-%m'))
plt.xticks(rotation=45)
ax.set_ylabel("Project Phases")
ax.set_xlabel("Timeline")
ax.set_title("Gantt Chart for SecureMSISDN Project")
plt.grid(visible=True, axis='x', linestyle='--', alpha=0.7)

plt.tight_layout()

# Save the updated Gantt chart as an image file
gantt_chart_path = "C:\\Users\\youss\\Desktop\\SecureMSISDN_Gantt_Chart.png"
fig.savefig(gantt_chart_path, format='png', dpi=300)
print(gantt_chart_path)

