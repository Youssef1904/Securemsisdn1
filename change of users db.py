import sqlite3

def migrate_users_scenario_a():
    """
    Migrates the existing 'users' table (where 'email' was PRIMARY KEY) 
    to a new schema that has 'user_id' as INTEGER PRIMARY KEY AUTOINCREMENT.
    """
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()

    # 1) Rename the old 'users' table
    cursor.execute("ALTER TABLE users RENAME TO old_users;")

    # 2) Create the new 'users' table with 'user_id' as the PRIMARY KEY
    #    Note that 'email' is now just a normal (or UNIQUE) column, not the PK.
    cursor.execute("""
        CREATE TABLE users (
            user_id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL,
            password TEXT NOT NULL,
            first_name TEXT NOT NULL,
            last_name TEXT NOT NULL,
            department TEXT NOT NULL,
            security_question TEXT,
            security_answer TEXT
        );
    """)

    # 3) Copy data from old_users to the new users table
    #    We omit 'user_id' because it is auto-incremented
    cursor.execute("""
        INSERT INTO users (email, password, first_name, last_name, department, security_question, security_answer)
        SELECT email, password, first_name, last_name, department, security_question, security_answer
        FROM old_users;
    """)

    # 4) (Optional) Drop the old table if everything looks good
    cursor.execute("DROP TABLE old_users;")

    conn.commit()
    conn.close()

if __name__ == "__main__":
    migrate_users_scenario_a()
    print("Migration to user_id primary key completed.")
