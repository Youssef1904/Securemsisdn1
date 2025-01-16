import ttkbootstrap as tb
from ttkbootstrap.constants import *
from tkinter import messagebox, filedialog, ttk
from PIL import Image, ImageTk
import pandas as pd
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
import base64
import os
import csv
import datetime
import sqlite3
import hashlib
import random
from tkinter import simpledialog
import subprocess
import platform
from ttkbootstrap.tableview import Tableview
import ttkbootstrap as tb
from tkinter import Tk
import ttkbootstrap as tb
from ttkbootstrap.style import Style
from tkinter import filedialog, messagebox, ttk
import ttkbootstrap as ttk
from ttkbootstrap.constants import *
import tkinter as tk
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
from tkinter import messagebox, Toplevel
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import base64
import os
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Util.Padding import pad, unpad
import os
import base64
from datetime import datetime
import tkinter as tk
from tkinter import Toplevel, messagebox
import datetime  



# Initialize the app with a dark theme
import ttkbootstrap as tb
from ttkbootstrap import Style
from tkinter import Tk
from key_request_function import request_access_window
# Initialize the app with a white theme
style = Style(theme="flatly")  # Start with a white-based theme
root = style.master
root.title("secureMSISDN")
root.iconbitmap('ooredooicon.ico')
root.geometry("500x500")

# Force pure white background
root.configure(background="white")





# Define the custom styles for buttons with specific size and no border for the red button
style.configure(
    "SmallRedButton.TButton",
    background="#d32f2f",          # Red background
    foreground="white",             # White text
    font=("Arial", 10, ),     # Smaller font size
    borderwidth=0,                  # No border
    focusthickness=0,               # No focus outline
)
style.configure(
    "WhiteButton.TButton",
    background="white", 
    foreground="#d32f2f", 
    font=("Arial", 10, ), 
    bordercolor="#d32f2f", 
    borderwidth=2
)



# Global variables
file_path = ""
files_data = []
current_user_department = ""
MASTER_KEY = os.getenv("MASTER_KEY") or b"16ByteMasterKey!"  # Example, must be securely stored

# Updated pool of security questions
SECURITY_QUESTIONS = [
    "What was the name of your first pet?",
    "What is your mother's maiden name?",
    "What is your favorite movie?",
    "What city were you born in?",
    "What was the make of your first car?"
]

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
            user_email TEXT NOT NULL,
            department TEXT NOT NULL,
            filename TEXT NOT NULL,
            file_size INTEGER NOT NULL,
            timestamp TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()


    
# Password hashing
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Password reset with security question
def forgot_password():
    email = simpledialog.askstring("Forgot Password", "Enter your email:")
    
    if email:
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        cursor.execute('SELECT security_question, security_answer FROM users WHERE email = ?', (email,))
        user_data = cursor.fetchone()

        if user_data:
            stored_question, stored_answer = user_data

            # Ask the user their security question
            answer = simpledialog.askstring("Security Question", f"{stored_question}:")
            
            if answer and answer.lower() == stored_answer.lower():
                new_password = simpledialog.askstring("New Password", "Enter a new password:", show='*')
                hashed_password = hash_password(new_password)
                
                cursor.execute('UPDATE users SET password = ? WHERE email = ?', (hashed_password, email))
                conn.commit()
                messagebox.showinfo("Success", "Password reset successfully!")
            else:
                messagebox.showerror("Error", "Incorrect security answer.")
        else:
            messagebox.showerror("Error", "Email not found.")
        conn.close()

# Load RSA keys
def load_rsa_keys():
    with open("public.pem", "rb") as pub_file:
        public_key = RSA.import_key(pub_file.read())
    with open("private.pem", "rb") as priv_file:
        private_key = RSA.import_key(priv_file.read())
    return public_key, private_key





AES_KEY_SIZE = 32  # 256-bit AES keys

# Generate new RSA key pair
def generate_new_key():
    try:
        new_key = RSA.generate(2048)
        with open("private.pem", "wb") as priv_file:
            priv_file.write(new_key.export_key())
        with open("public.pem", "wb") as pub_file:
            pub_file.write(new_key.public_key().export_key())
        return "New key pair generated successfully."
    except Exception as e:
        return f"Error: {e}"

# Import an existing private key
def import_key(file_path):
    try:
        with open(file_path, "rb") as key_file:
            key = key_file.read()
        with open("private.pem", "wb") as priv_file:
            priv_file.write(key)
        return "Key imported successfully."
    except Exception as e:
        return f"Error: {e}"

# Export a specified RSA key
def export_key(key_type="private"):
    try:
        file_name = "private.pem" if key_type == "private" else "public.pem"
        with open(file_name, "rb") as key_file:
            return key_file.read()
    except Exception as e:
        return f"Error: {e}"

# View metadata of the private key
def view_key_metadata():
    try:
        file_stats = os.stat("private.pem")
        metadata = {
            "Key Type": "Private Key",
            "Size": file_stats.st_size,
            "Created On": datetime.fromtimestamp(file_stats.st_ctime),
            "Last Modified": datetime.fromtimestamp(file_stats.st_mtime),
        }
        return metadata
    except FileNotFoundError:
        return "No key found. Please generate or import a key."

# Inspect the current encryption key
def inspect_encryption_key():
    try:
        if not os.path.exists('encrypted_aes_key.bin'):
            raise FileNotFoundError("The encrypted AES key file ('encrypted_aes_key.bin') was not found.")

        with open('encrypted_aes_key.bin', 'rb') as f:
            encrypted_aes_key = f.read()

        with open('private.pem', 'rb') as priv_file:
            private_key = RSA.import_key(priv_file.read())

        cipher_rsa = PKCS1_OAEP.new(private_key)
        aes_key = cipher_rsa.decrypt(encrypted_aes_key)

        return aes_key
    except Exception as e:
        messagebox.showerror("Error", str(e))

# Regenerate and save a new AES encryption key
def regenerate_encryption_key():
    try:
        new_aes_key = os.urandom(AES_KEY_SIZE)
        with open('public.pem', 'rb') as pub_file:
            public_key = RSA.import_key(pub_file.read())

        cipher_rsa = PKCS1_OAEP.new(public_key)
        encrypted_new_aes_key = cipher_rsa.encrypt(new_aes_key)

        with open('encrypted_aes_key.bin', 'wb') as f:
            f.write(encrypted_new_aes_key)

        messagebox.showinfo("Success", "New AES key generated and saved for future encryption operations.")
    except Exception as e:
        messagebox.showerror("Error", f"Key regeneration failed: {e}")

# Key management window
def open_key_management_window():
    key_window = Toplevel()
    key_window.title("Key Management")
    key_window.geometry("400x300")

    inspect_btn = tk.Button(
        key_window,
        text="Inspect Encryption Key",
        command=lambda: messagebox.showinfo(
            "Key Details",
            f"Current Key: {base64.b64encode(inspect_encryption_key()).decode('utf-8')}"
        ),
        bg="red", fg="white", font=("Arial", 12, "bold")
    )
    inspect_btn.pack(pady=10)

    regenerate_btn = tk.Button(
        key_window,
        text="Regenerate Encryption Key",
        command=regenerate_encryption_key,
        bg="black", fg="white", font=("Arial", 12, "bold")
    )
    regenerate_btn.pack(pady=10)

    close_btn = tk.Button(
        key_window,
        text="Close",
        command=key_window.destroy,
        bg="gray", fg="white", font=("Arial", 12, "bold")
    )
    close_btn.pack(pady=10)

# Encrypt a given key using AES
def encrypt_key(key: bytes, master_key: bytes) -> str:
    try:
        cipher = AES.new(master_key, AES.MODE_ECB)
        encrypted = cipher.encrypt(pad(key, AES.block_size))
        return base64.b64encode(encrypted).decode('utf-8')
    except Exception as e:
        raise ValueError(f"Error encrypting key: {e}")

# Decrypt the key using AES
def decrypt_key(encrypted_key: str, master_key: bytes) -> bytes:
    try:
        cipher = AES.new(master_key, AES.MODE_ECB)
        decrypted = unpad(cipher.decrypt(base64.b64decode(encrypted_key)), AES.block_size)
        return decrypted
    except Exception as e:
        raise ValueError(f"Error decrypting key: {e}")

# Usage Example
if __name__ == "__main__":
    try:
        aes_key = os.urandom(AES_KEY_SIZE)  # Generate a valid AES key
        encrypted_aes_key = encrypt_key(aes_key, MASTER_KEY)
        print("Encrypted AES Key:", encrypted_aes_key)

        decrypted_aes_key = decrypt_key(encrypted_aes_key, MASTER_KEY)
        print("Decrypted AES Key:", decrypted_aes_key)
    except Exception as e:
        print("Error:", e)



def add_logo(frame):
    try:
        # Open the logo with a transparent background
        logo_img = Image.open(r"C:\Users\youss\ooredoo_logo.png")
        
        # Resize proportionally based on app dimensions
        logo_width, logo_height = logo_img.size
        new_width = 200  # Adjust based on your layout
        new_height = int((new_width / logo_width) * logo_height)
        logo_img = logo_img.resize((new_width, new_height), Image.LANCZOS)
        
        # Convert to a Tkinter-compatible image
        logo_photo = ImageTk.PhotoImage(logo_img)
        logo_label = tb.Label(frame, image=logo_photo, background='white')  # Set background to match the app
        logo_label.image = logo_photo  # Keep a reference to avoid garbage collection
        logo_label.pack(pady=10)
        
    except Exception as e:
        print(f"Error loading logo: {e}")


    


    
    
# Ensure the cursor is available globally
def init_db():
    global conn, cursor
    conn = sqlite3.connect('app_data.db')
    cursor = conn.cursor()
    create_file_activity_table()  # Call this to create the table if it doesn't exist


def open_file(filename):
    file_path = os.path.join(os.getcwd(), filename)
    
    try:
        if platform.system() == 'Windows':
            os.startfile(file_path)
        elif platform.system() == 'Darwin':  # macOS
            subprocess.call(('open', file_path))
        else:  # Linux
            subprocess.call(('xdg-open', file_path))
    except Exception as e:
        messagebox.showerror("Error", f"Unable to open file: {e}")
        
# Import datetime module correctly
import datetime

def log_file_activity(user_email, department, filename, file_size, key, activity_type="Encryption"):
    """
    Logs a file activity (encryption or decryption) into the database.

    Parameters:
        user_email (str): Email of the user performing the activity.
        department (str): Department of the user.
        filename (str): Name of the file being encrypted or decrypted.
        file_size (int): Size of the file in bytes.
        key (str): The key used for encryption or decryption (will be encrypted before saving).
        activity_type (str): Type of activity ("Encryption" or "Decryption"). Default is "Encryption".
    """
    try:
        # Connect to the SQLite database
        conn = sqlite3.connect('app_data.db')
        cursor = conn.cursor()

        # Get the current timestamp
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Encrypt the key before saving (pass the master_key)
        encrypted_key = encrypt_key(key.encode('utf-8'), MASTER_KEY)

        # Insert the activity log into the database
        cursor.execute('''
            INSERT INTO file_activities (user_email, department, filename, file_size, timestamp, key_used, activity_type)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (user_email, department, filename, file_size, timestamp, encrypted_key, activity_type))

        # Commit changes and close connection
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Error logging file activity: {e}")





# Function to handle file upload
def upload_file():
    global file_path
    file_path = filedialog.askopenfilename(filetypes=[("Excel files", "*.xlsx")])
    if file_path:
        messagebox.showinfo("File Selected", f"File selected: {file_path}")




def encrypt_data():
    try:
        if not file_path:
            messagebox.showerror("Error", "Please upload an Excel file first.")
            return

        # Load RSA public key
        public_key, _ = load_rsa_keys()

        # Load the Excel file into a DataFrame
        df = pd.read_excel(file_path)

        # Check if 'MSISDN' column is present
        if 'MSISDN' not in df.columns:
            messagebox.showerror("Error", "'MSISDN' column not found in the Excel file.")
            return

        # Ensure MSISDN column is treated as strings
        df['MSISDN'] = df['MSISDN'].astype(str)

        # Generate AES key
        aes_key = os.urandom(16)

        # Encrypt AES key using the RSA public key
        cipher_rsa = PKCS1_OAEP.new(public_key)
        encrypted_aes_key = cipher_rsa.encrypt(aes_key)

        # Save the encrypted AES key with the encrypted file name
        encrypted_file_path = filedialog.asksaveasfilename(defaultextension=".xlsx", filetypes=[("Excel files", "*.xlsx")])
        if not encrypted_file_path:
            messagebox.showerror("Error", "Please specify a valid file path to save the encrypted data.")
            return

        aes_key_file = os.path.splitext(encrypted_file_path)[0] + "_aes_key.bin"
        with open(aes_key_file, 'wb') as f:
            f.write(encrypted_aes_key)

        # Encrypt each MSISDN value
        def encrypt_msisdn(msisdn, aes_key):
            cipher_aes = AES.new(aes_key, AES.MODE_EAX)
            nonce = cipher_aes.nonce
            ciphertext, tag = cipher_aes.encrypt_and_digest(msisdn.encode('utf-8'))
            return base64.b64encode(nonce + tag + ciphertext).decode('utf-8')

        # Create Encrypted_MSISDN column
        df['Encrypted_MSISDN'] = df['MSISDN'].apply(lambda msisdn: encrypt_msisdn(msisdn, aes_key))

        # Remove original MSISDN column
        df.drop(columns=['MSISDN'], inplace=True)

        # Save the encrypted file
        df.to_excel(encrypted_file_path, index=False)

        # Provide feedback
        messagebox.showinfo("Success", f"Data encrypted and saved to {encrypted_file_path}\nAES key saved to {aes_key_file}")

        # Log the file activity into the database
        log_file_activity(
            user_email=current_user_email,
            department=current_user_department,
            filename=os.path.basename(encrypted_file_path),
            file_size=os.path.getsize(encrypted_file_path),
            key=base64.b64encode(aes_key).decode('utf-8'),
            activity_type="Encryption"
        )
    except Exception as e:
        messagebox.showerror("Error", f"Encryption failed: {e}")



def decrypt_data():
    try:
        if not file_path:
            messagebox.showerror("Error", "Please upload an encrypted Excel file first.")
            return

        # Determine the associated AES key file path
        key_file_path = os.path.splitext(file_path)[0] + "_aes_key.bin"
        if not os.path.exists(key_file_path):
            messagebox.showerror("Error", f"AES key file not found for {os.path.basename(file_path)}.")
            return

        # Load the private RSA key
        with open('private.pem', 'rb') as f:
            private_key = RSA.import_key(f.read())

        # Load and decrypt the AES key
        with open(key_file_path, 'rb') as f:
            encrypted_aes_key = f.read()
        cipher_rsa = PKCS1_OAEP.new(private_key)
        aes_key = cipher_rsa.decrypt(encrypted_aes_key)

        # Load the encrypted Excel data
        df = pd.read_excel(file_path)

        # Check if 'Encrypted_MSISDN' column is present
        if 'Encrypted_MSISDN' not in df.columns:
            messagebox.showerror("Error", "'Encrypted_MSISDN' column not found in the Excel file.")
            return

        # Decrypt each Encrypted_MSISDN value
        def decrypt_msisdn(enc_msisdn, aes_key):
            data = base64.b64decode(enc_msisdn)
            nonce, tag, ciphertext = data[:16], data[16:32], data[32:]
            cipher_aes = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
            return cipher_aes.decrypt_and_verify(ciphertext, tag).decode('utf-8')

        # Create decrypted MSISDN column
        df['MSISDN'] = df['Encrypted_MSISDN'].apply(lambda enc_msisdn: decrypt_msisdn(enc_msisdn, aes_key))

        # Remove Encrypted_MSISDN column
        df.drop(columns=['Encrypted_MSISDN'], inplace=True)

        # Save the decrypted file
        decrypted_file_path = filedialog.asksaveasfilename(defaultextension=".xlsx", filetypes=[("Excel files", "*.xlsx")])
        if not decrypted_file_path:
            messagebox.showerror("Error", "Please specify a valid file path to save the decrypted data.")
            return

        df.to_excel(decrypted_file_path, index=False)

        # Provide feedback
        messagebox.showinfo("Success", f"Data decrypted and saved to {decrypted_file_path}")

        # Log the file activity
        log_file_activity(
            user_email=current_user_email,
            department=current_user_department,
            filename=os.path.basename(decrypted_file_path),
            file_size=os.path.getsize(decrypted_file_path),
            key=base64.b64encode(aes_key).decode('utf-8'),
            activity_type="Decryption"
        )
    except Exception as e:
        messagebox.showerror("Error", f"Decryption failed: {e}")





# Function to simulate cloud upload
def simulate_upload():
    messagebox.showinfo("Cloud Upload", "Simulated upload to cloud server completed!")

def view_all_users():
    global root
    for widget in root.winfo_children():
        widget.destroy()

    user_frame = tb.Frame(root, padding=(20, 10), bootstyle="secondary")
    user_frame.pack(fill="both", expand=True)

    tb.Label(user_frame, text="All Registered Users", bootstyle="info").pack(pady=10)

    users = get_all_users()  # Function that fetches all users from the database
    columns = ('first_name', 'last_name', 'email')
    user_table = Tableview(
        master=user_frame,
        coldata=columns,
        rowdata=[[user['first_name'], user['last_name'], user['email']] for user in users],
        bootstyle="info"
    )
    user_table.pack(pady=10, fill='both', expand=True)

    # Button to remove users
    tb.Button(user_frame, text="Remove Selected User", command=lambda: remove_selected_user(user_table), bootstyle="danger-outline").pack(pady=10)

    # Return button to go back to the dashboard
    tb.Button(user_frame, text="Return", command=show_dashboard, bootstyle="secondary-outline").pack(pady=10)

def remove_selected_user(table):
    selected = table.get_selected()
    if selected:
        user_email = selected[0][2]  # Email is in the 3rd column
        remove_user(user_email)  # Call the remove_user function to delete the user
        messagebox.showinfo("Success", f"User {user_email} has been removed.")
    else:
        messagebox.showerror("Error", "No user selected.")


def show_dashboard():
    global current_user_department, last_page

    if current_user_department != 'Admin':
        messagebox.showerror("Access Denied", "Only admins can access the dashboard.")
        return

    # Clear previous frame
    for widget in root.winfo_children():
        widget.destroy()

    dashboard_frame = tb.Frame(root, padding=(20, 10), bootstyle="secondary")
    dashboard_frame.pack(fill="both", expand=True)

    # Title for the dashboard
    tb.Label(dashboard_frame, text="Admin Dashboard - File Activities", bootstyle="info", font=("Arial", 18, "bold")).pack(pady=10)

    try:
        # Fetch file activities from the database
        conn = sqlite3.connect('app_data.db')
        cursor = conn.cursor()
        cursor.execute("""
            SELECT user_email, department, filename, file_size, timestamp, key_used, activity_type
            FROM file_activities
        """)
        file_activities = cursor.fetchall()

        # Process keys to obfuscate them for security
        file_activities = [
            (
                email,
                dept,
                fname,
                fsize,
                timestamp,
                f"******{key[-4:]}" if key and len(key) >= 4 else "N/A",
                activity
            )
            for email, dept, fname, fsize, timestamp, key, activity in file_activities
        ]

    except Exception as e:
        messagebox.showerror("Database Error", f"Failed to fetch file activities: {e}")
        return
    finally:
        if conn:
            conn.close()

    # Table Columns
    columns = ('User Email', 'Department', 'File Name', 'File Size (Bytes)', 'Timestamp', 'Key Used', 'Activity Type')

    # Create TableView
    file_table = Tableview(
        master=dashboard_frame,
        coldata=columns,
        rowdata=file_activities,
        paginated=True,
        searchable=True,
        bootstyle="success"
    )
    file_table.pack(pady=10, fill='both', expand=True)

    # View All Users button
    tb.Button(dashboard_frame, text="View All Users", command=view_all_users, bootstyle="secondary-outline").pack(pady=10)

    # Key Management button
    tb.Button(
        dashboard_frame,
        text="Key Management",
        command=open_key_management_window,
        bootstyle="warning-outline"
    ).pack(pady=10)

    # Dynamic Return button
    def navigate_back():
        if last_page == "encryption":
            create_main_page(is_encryption=True)
        elif last_page == "decryption":
            create_main_page(is_encryption=False)

    tb.Button(
        dashboard_frame,
        text="Return",
        command=navigate_back,
        bootstyle="secondary-outline"
    ).pack(pady=10)


# Fetch all users from SQLite
def get_all_users():
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute("SELECT first_name, last_name, email FROM users")
    users = cursor.fetchall()
    conn.close()
    return [{'first_name': user[0], 'last_name': user[1], 'email': user[2]} for user in users]


# Remove user
def remove_user(email):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute("DELETE FROM users WHERE email = ?", (email,))
    conn.commit()
    conn.close()
    show_dashboard()

# Call init_db() when the app starts to ensure the database is ready
init_db()


def create_main_page(is_encryption=True):
    global current_user_department, last_page

    # Set last_page based on the current mode
    last_page = "encryption" if is_encryption else "decryption"

    for widget in root.winfo_children():
        widget.destroy()

    main_frame = tb.Frame(root, padding=(20, 10), bootstyle="white")
    main_frame.pack(fill="both", expand=True)

    add_logo(main_frame)

    # Change button text and function based on whether encryption or decryption was selected
    if is_encryption:
        tb.Button(main_frame, text="Upload Excel File", command=upload_file, style="SmallRedButton.TButton").pack(pady=10)
        tb.Button(main_frame, text="Encrypt Data", command=encrypt_data, style="SmallRedButton.TButton").pack(pady=10)
        tb.Button(main_frame, text="Simulate Cloud Upload", command=simulate_upload, style="SmallRedButton.TButton").pack(pady=10)   
    else:
        tb.Button(main_frame, text="Simulate Cloud download", command=simulate_upload, style="SmallRedButton.TButton").pack(pady=10)
        tb.Button(main_frame, text="Upload Excel File", command=upload_file, style="SmallRedButton.TButton").pack(pady=10)
        tb.Button(main_frame, text="Decrypt Data", command=decrypt_data, style="SmallRedButton.TButton").pack(pady=10)

    if current_user_department == 'Admin':
        tb.Button(main_frame, text="Admin Dashboard", command=show_dashboard, style="SmallRedButton.TButton").pack(pady=10)
    else:
        request_key_button = tk.Button(root, text="Request Data Access", command=lambda: request_access_window(current_user_id))
        request_key_button.pack(pady=10)

    tb.Button(main_frame, text="Sign Out", command=create_signin_page, bootstyle="danger-outline").pack(side="top", anchor="nw", padx=10, pady=10)

def create_signup_page():
    for widget in root.winfo_children():
        widget.destroy()

    # Create a canvas and a scrollbar for scrolling functionality
    canvas = tb.Canvas(root)  # Removed bootstyle from here
    scrollbar = tb.Scrollbar(root, orient="vertical", command=canvas.yview)
    scrollable_frame = tb.Frame(canvas, padding=(20, 10), bootstyle="white")

    scrollable_frame.bind(
        "<Configure>",
        lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
    )

    canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
    canvas.configure(yscrollcommand=scrollbar.set)

    canvas.pack(side="left", fill="both", expand=True)
    scrollbar.pack(side="right", fill="y")

    # Organize widgets within the scrollable_frame
    # Add logo
    add_logo(scrollable_frame)

    def create_signup_page():
        for widget in root.winfo_children():
            widget.destroy()

        # Create a canvas and a scrollbar for scrolling functionality
        canvas = tb.Canvas(root)  # Removed bootstyle from here
        scrollbar = tb.Scrollbar(root, orient="vertical", command=canvas.yview)
        scrollable_frame = tb.Frame(canvas, padding=(20, 10), bootstyle="white")

        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )

        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        # Organize widgets within the scrollable_frame
        # Add logo
        add_logo(scrollable_frame)

    def submit_signup():
        first_name = entry_first_name.get()
        last_name = entry_last_name.get()
        email = entry_email.get()
        password = entry_password.get()
        confirm_password = entry_confirm_password.get()
        department = department_var.get()
        security_question = security_question_var.get()
        security_answer = entry_security_answer.get()

        if password != confirm_password:
            messagebox.showerror("Error", "Passwords do not match.")
            return

        hashed_password = hash_password(password)

        try:
            conn = sqlite3.connect('users.db')
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO users (email, password, first_name, last_name, department, security_question, security_answer)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (email, hashed_password, first_name, last_name, department, security_question, security_answer))
            conn.commit()
            conn.close()
            messagebox.showinfo("Success", "User registered successfully!")
        except sqlite3.IntegrityError:
            messagebox.showerror("Error", "User already exists.")

        create_signin_page()

    # Organizing fields using `pack()` to avoid mix of geometry managers
    tb.Label(scrollable_frame, text="First Name:", bootstyle="info").pack(anchor="w", padx=10, pady=5)
    entry_first_name = tb.Entry(scrollable_frame)
    entry_first_name.pack(fill="x", padx=10, pady=5)

    tb.Label(scrollable_frame, text="Last Name:", bootstyle="info").pack(anchor="w", padx=10, pady=5)
    entry_last_name = tb.Entry(scrollable_frame)
    entry_last_name.pack(fill="x", padx=10, pady=5)

    tb.Label(scrollable_frame, text="Email:", bootstyle="info").pack(anchor="w", padx=10, pady=5)
    entry_email = tb.Entry(scrollable_frame)
    entry_email.pack(fill="x", padx=10, pady=5)

    tb.Label(scrollable_frame, text="Password:", bootstyle="info").pack(anchor="w", padx=10, pady=5)
    entry_password = tb.Entry(scrollable_frame, show="*")
    entry_password.pack(fill="x", padx=10, pady=5)

    tb.Label(scrollable_frame, text="Confirm Password:", bootstyle="info").pack(anchor="w", padx=10, pady=5)
    entry_confirm_password = tb.Entry(scrollable_frame, show="*")
    entry_confirm_password.pack(fill="x", padx=10, pady=5)

    tb.Label(scrollable_frame, text="Department:", bootstyle="info").pack(anchor="w", padx=10, pady=5)
    department_var = tb.StringVar(value="Marketing")
    departments = [("Marketing", "Marketing"), ("IT", "IT"), ("Infrastructure", "Infrastructure"), ("Admin", "Admin")]
    for text, value in departments:
        tb.Radiobutton(scrollable_frame, text=text, variable=department_var, value=value, bootstyle="danger-toolbutton").pack(anchor="w", padx=10, pady=5)

    # Security Question and Answer
    security_question_var = tb.StringVar(value="Which is your favorite movie?")
    security_questions = [
        "Which is your favorite movie?",
        "What was your first pet's name?",
        "What is your mother's maiden name?",
        "What is the name of your first school?",
        "What is your favorite food?"
    ]

    tb.Label(scrollable_frame, text="Security Question:", bootstyle="info").pack(anchor="w", padx=10, pady=5)
    question_menu = tb.OptionMenu(scrollable_frame, security_question_var, *security_questions)
    question_menu.pack(fill="x", padx=10, pady=5)

    tb.Label(scrollable_frame, text="Answer:", bootstyle="info").pack(anchor="w", padx=10, pady=5)
    entry_security_answer = tb.Entry(scrollable_frame)
    entry_security_answer.pack(fill="x", padx=10, pady=5)

    tb.Button(scrollable_frame, text="Sign Up", command=submit_signup, bootstyle="success").pack(fill="x", pady=20)

    # Return button to sign-in page
    tb.Button(scrollable_frame, text="Return", command=create_signin_page, bootstyle="secondary-outline").pack(fill="x", pady=10)

def create_signin_page():
    global entry_email, entry_password  # Declare widgets globally if needed

    # Clear any existing widgets from the root window
    for widget in root.winfo_children():
        widget.destroy()

    # Create a new frame for the sign-in page
    signin_frame = tb.Frame(root, padding=(20, 10), bootstyle="white")
    signin_frame.pack(fill="both", expand=True)

    add_logo(signin_frame)  # Assuming there's a function to add the logo

    # Create labels and entry widgets for the sign-in page
    tb.Label(signin_frame, text="Email:", bootstyle="info").pack(pady=5)
    entry_email = tb.Entry(signin_frame)
    entry_email.pack(pady=5)

    tb.Label(signin_frame, text="Password:", bootstyle="info").pack(pady=5)
    entry_password = tb.Entry(signin_frame, show="*")
    entry_password.pack(pady=5)

    # Sign In button that triggers the sign-in logic
    tb.Button(signin_frame, text="Sign In", command=submit_signin, style="SmallRedButton.TButton").pack(pady=20)

    # Forgot password button
    tb.Button(signin_frame, text="Forgot Password?", command=forgot_password, style="WhiteButton.TButton").pack(pady=5)

    # Sign-up button
    tb.Button(signin_frame, text="Sign Up", command=create_signup_page, style="SmallRedButton.TButton").pack(pady=5)


def submit_signin():
    # Retrieve email and password from the entry fields
    email = entry_email.get()
    password = entry_password.get()

    # Hash the entered password
    hashed_password = hash_password(password)

    # Connect to the database
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()

    # Query for the user's credentials
    cursor.execute('SELECT password, department FROM users WHERE email = ?', (email,))
    result = cursor.fetchone()

    # If credentials are valid, store global variables and go to the operation choice page
    if result and result[0] == hashed_password:
        global current_user_email, current_user_department
        current_user_email = email  # Store the signed-in user's email globally
        current_user_department = result[1]  # Store the department

        messagebox.showinfo("Success", "Sign-in successful!")

        # Navigate to the operation choice page (choose between encryption or decryption)
        create_operation_choice_page()  # This function will be implemented to choose between operations
    else:
        messagebox.showerror("Error", "Invalid email or password.")

    conn.close()

# Function to navigate to the operation choice page
def create_operation_choice_page():
    for widget in root.winfo_children():
        widget.destroy()

    choice_frame = tb.Frame(root, padding=(20, 10), bootstyle="white")
    choice_frame.pack(fill="both", expand=True)

    tb.Label(choice_frame, text="Choose Operation", bootstyle="info").pack(pady=10)

    # Use lambda to pass the correct parameter when the button is clicked
    tb.Button(choice_frame, text="Encryption", command=lambda: create_main_page(is_encryption=True), style="SmallRedButton.TButton").pack(pady=10)
    tb.Button(choice_frame, text="Decryption", command=lambda: create_main_page(is_encryption=False), style="SmallRedButton.TButton").pack(pady=10)

    tb.Button(choice_frame, text="Sign Out", command=create_signin_page, bootstyle="danger-outline").pack(pady=10)


# Call this function when the application starts to show the sign-in page
create_signin_page()



# Create the user table when the app starts
# Initialize the app and create necessary tables
create_user_table()
create_file_activity_table()

# Start with the sign-in page
create_signin_page()

root.mainloop()

