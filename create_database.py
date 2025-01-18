import sqlite3

def create_user_table():
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            user_id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL,
            password TEXT NOT NULL,
            first_name TEXT NOT NULL,
            last_name TEXT NOT NULL,
            department TEXT NOT NULL,
            security_question TEXT,
            security_answer TEXT
        )
    ''')
    conn.commit()
    conn.close()
    

def create_file_activity_table():
    conn = sqlite3.connect('app_data.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS file_activities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            user_email TEXT NOT NULL,
            department TEXT NOT NULL,
            filename TEXT NOT NULL,
            file_size INTEGER NOT NULL,
            timestamp TEXT NOT NULL,
            activity_type TEXT NOT NULL,
            key TEXT
        )
    ''')
    conn.commit()
    conn.close()



def create_database():
    conn = sqlite3.connect("ooredoo.db")
    cursor = conn.cursor()

    # Existing tables (Users, Encrypted_Data_Logs, etc.) are created here...

    # === NEW TABLE FOR KEY REQUESTS ===
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS key_requests (
        request_id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        file_name TEXT NOT NULL,
        request_reason TEXT,
        status TEXT DEFAULT 'PENDING',   -- PENDING, APPROVED, REJECTED
        admin_id INTEGER,
        request_timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        approval_timestamp DATETIME,
        ack_received BOOLEAN DEFAULT 0,
        ack_timestamp DATETIME
    );
    """)

    conn.commit()
    conn.close()

if __name__ == "__main__":
    create_database()
# Create the user table when the app starts
# Initialize the app and create necessary tables
create_user_table()
create_file_activity_table()
