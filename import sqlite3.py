import sqlite3

def check_file_activities():
    conn = sqlite3.connect('app_data.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM file_activities')
    
    activities = cursor.fetchall()
    conn.close()
    return activities

# Run the check
file_activities = check_file_activities()
print(f"File activities in database: {file_activities}")

