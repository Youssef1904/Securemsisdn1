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


import sqlite3

# --------------------- Step 1: Recreate Database and Tables ---------------------
def create_database():
    conn = sqlite3.connect('ooredoo_equipements.db')
    cursor = conn.cursor()

    # Enable foreign key support
    cursor.execute("PRAGMA foreign_keys = ON")

    # Drop existing tables (for fresh creation)
    cursor.execute("DROP TABLE IF EXISTS Equipments")
    cursor.execute("DROP TABLE IF EXISTS Categories")

    # Create Categories Table
    cursor.execute('''
        CREATE TABLE Categories (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE
        )
    ''')

    # Create Equipments Table with Foreign Key Reference to Categories
    cursor.execute('''
        CREATE TABLE Equipments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            category_id INTEGER NOT NULL,
            manufacturer TEXT NOT NULL,
            model TEXT NOT NULL,
            serial_number TEXT NOT NULL UNIQUE,
            purchase_date DATE NOT NULL,
            warranty_end_date DATE,
            status TEXT NOT NULL CHECK(status IN ('Active', 'In Maintenance', 'Decommissioned')),
            location TEXT NOT NULL,
            assigned_project TEXT,
            FOREIGN KEY (category_id) REFERENCES Categories(id) ON DELETE CASCADE
        )
    ''')
    
     # Create Maintenance Schedule Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS MaintenanceSchedule (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            equipment_id INTEGER NOT NULL,
            maintenance_date TEXT NOT NULL,  -- Store dates as TEXT,
            status TEXT NOT NULL CHECK(status IN ('Scheduled', 'Completed' , 'overdue')),
            notes TEXT,
            FOREIGN KEY (equipment_id) REFERENCES Equipments(id) ON DELETE CASCADE
        )
    ''')

    conn.commit()
    conn.close()
    print("✅ Database and tables created successfully!")


# --------------------- Step 2: Insert Category Data ---------------------
def insert_categories():
    conn = sqlite3.connect('ooredoo_equipements.db')
    cursor = conn.cursor()

    categories = [
        ("Réseaux d'accès (fixe et mobile)",),
        ("Réseaux IP et transmission",),
        ("Réseaux coeurs",),
        ("Réseaux IN et VAS",)
    ]
    
    cursor.executemany("INSERT OR IGNORE INTO Categories (name) VALUES (?)", categories)

    conn.commit()
    conn.close()
    print("✅ Categories inserted successfully!")


# --------------------- Step 3: Insert Equipment Data ---------------------
def insert_equipments():
    conn = sqlite3.connect('ooredoo_equipements.db')
    cursor = conn.cursor()

    equipments_data = [
        ("Fiber Optic Router", "Réseaux d'accès (fixe et mobile)", "Cisco", "FGX-1200", "SN12345", "2023-05-10", "2025-05-10", "Active", "Tunis HQ", "Project Alpha"),
        ("Base Transceiver Station", "Réseaux d'accès (fixe et mobile)", "Ericsson", "BTS-900", "SN67890", "2022-03-15", "2026-03-15", "Active", "Sousse Branch", "Project Beta"),
        ("Core Router", "Réseaux coeurs", "Juniper", "MX480", "SN11111", "2021-07-20", "2025-07-20", "In Maintenance", "Tunis Data Center", "Project Gamma"),
        ("IP Switch", "Réseaux IP et transmission", "Huawei", "S6720", "SN22222", "2020-01-10", "2024-01-10", "Decommissioned", "Sfax Branch", None),
        ("IN Server", "Réseaux IN et VAS", "Dell", "PowerEdge R740", "SN33333", "2023-11-01", "2026-11-01", "Active", "Tunis HQ", "Project Delta"),
        ("Transmission Node", "Réseaux IP et transmission", "Alcatel-Lucent", "TN-110", "SN44444", "2021-09-05", "2024-09-05", "Active", "Monastir Branch", "Project Epsilon"),
    ]

    for equipment in equipments_data:
        name, category_name, manufacturer, model, serial_number, purchase_date, warranty_end_date, status, location, assigned_project = equipment

        # Get category_id from category name
        cursor.execute("SELECT id FROM Categories WHERE name = ?", (category_name,))
        category_id = cursor.fetchone()

        if category_id:
            try:
                cursor.execute('''
                    INSERT INTO Equipments (name, category_id, manufacturer, model, serial_number, purchase_date, 
                                            warranty_end_date, status, location, assigned_project)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (name, category_id[0], manufacturer, model, serial_number, purchase_date, warranty_end_date, status, location, assigned_project))
                print(f"✅ Inserted equipment: {name}")
            except sqlite3.IntegrityError as e:
                print(f"❌ Error inserting equipment '{name}': {e}")
        else:
            print(f"❌ Category not found for equipment '{name}'")

    conn.commit()
    conn.close()
    print("✅ Equipment data inserted successfully!")


# --------------------- Execute All Steps ---------------------
if __name__ == "__main__":
    create_database()
    insert_categories()
    insert_equipments()




