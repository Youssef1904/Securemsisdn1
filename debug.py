import sqlite3

# Connect to SQLite database
conn = sqlite3.connect('ooredoo_equipements.db')
cursor = conn.cursor()

# Enable foreign key support
cursor.execute("PRAGMA foreign_keys = ON")

# Check if the column `category_id` exists
cursor.execute("PRAGMA table_info(Equipments)")
columns = [column[1] for column in cursor.fetchall()]

if "category_id" not in columns:
    # Add the new column for category mapping
    cursor.execute("ALTER TABLE Equipments ADD COLUMN category_id INTEGER REFERENCES Categories(id)")

conn.commit()
conn.close()

print("Database schema updated: 'category_id' column added successfully!")
