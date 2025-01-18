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
        


def log_file_activity(user_id, user_email, department, filename, file_size, key, activity_type="Encryption"):
    """
    Logs a file activity (encryption or decryption) into the file_activities table.
    
    Table Schema (file_activities):
    -------------------------------------------------
    id            INTEGER PRIMARY KEY AUTOINCREMENT
    user_id       INTEGER NOT NULL
    user_email    TEXT NOT NULL
    department    TEXT NOT NULL
    filename      TEXT NOT NULL
    file_size     INTEGER NOT NULL
    timestamp     TEXT NOT NULL
    activity_type TEXT NOT NULL
    key           TEXT
    -------------------------------------------------

    Parameters:
        user_id (int): The auto-increment PK of the user performing the activity.
        user_email (str): The email of the user.
        department (str): The department of the user.
        filename (str): The name of the file being encrypted or decrypted.
        file_size (int): The size of the file in bytes.
        key (str): The key used for encryption or decryption (will be encrypted before saving).
        activity_type (str): "Encryption" or "Decryption" (default: "Encryption").
    """
    try:
        # Connect to the SQLite database
        conn = sqlite3.connect('app_data.db')
        cursor = conn.cursor()

        # Get the current timestamp
        current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Encrypt the key before saving, assuming encrypt_key() and MASTER_KEY exist
        encrypted_key = encrypt_key(key.encode('utf-8'), MASTER_KEY)

        # Insert the activity log into the database
        cursor.execute('''
            INSERT INTO file_activities (
                user_id, user_email, department, filename, file_size, timestamp, activity_type, key
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (user_id, user_email, department, filename, file_size, current_time, activity_type, encrypted_key))

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

def open_document_encryption_tool():
    tool_window = tk.Toplevel()
    tool_window.title("Document Encryption Tool")
    tool_window.geometry("800x600")

    tk.Label(tool_window, text="Upload a Word or Excel file:", font=("Arial", 12)).pack(pady=10)
    file_path_var = tk.StringVar()

    def upload_document():
        file_path = filedialog.askopenfilename(
            filetypes=[("Word and Excel Files", "*.docx *.xlsx"), ("Word Documents", "*.docx"), ("Excel Files", "*.xlsx")]
        )
        if file_path:
            file_path_var.set(file_path)
            process_document(file_path)

    tk.Button(tool_window, text="Upload Document", command=upload_document).pack(pady=10)
    tk.Entry(tool_window, textvariable=file_path_var, state="readonly", width=60).pack(pady=5)

    content_frame = tk.Frame(tool_window)
    content_frame.pack(fill="both", expand=True, padx=10, pady=10)

    def process_document(file_path):
        # Clear the content_frame
        for widget in content_frame.winfo_children():
            widget.destroy()

        # Check file extension and process accordingly
        if file_path.endswith(".xlsx"):
            display_excel_content(file_path, content_frame)
        elif file_path.endswith(".docx"):
            display_word_content(file_path, content_frame)
        else:
            messagebox.showerror("Error", "Unsupported file type. Please upload a .docx or .xlsx file.")

    tk.Button(tool_window, text="Return", command=tool_window.destroy).pack(pady=10)

def display_excel_content(file_path, parent_frame):
    import pandas as pd

    try:
        # Load Excel data
        df = pd.read_excel(file_path)

        # Treeview for data preview (enable cell selection)
        tree = ttk.Treeview(parent_frame, selectmode="none")
        tree.pack(side="left", fill="both", expand=True)

        # Scrollbar for Treeview
        tree_scroll = ttk.Scrollbar(parent_frame, orient="vertical", command=tree.yview)
        tree_scroll.pack(side="left", fill="y")
        tree.configure(yscrollcommand=tree_scroll.set)

        # Configure columns
        tree["columns"] = list(df.columns)
        tree["show"] = "headings"

        for col in df.columns:
            tree.heading(col, text=col)
            tree.column(col, width=100)

        # Insert rows
        for idx, row in df.iterrows():
            tree.insert("", "end", values=list(row))

        # Listbox to show selected cells
        listbox_frame = tk.Frame(parent_frame)
        listbox_frame.pack(side="right", fill="both", expand=True, padx=10)
        tk.Label(listbox_frame, text="Selected Cells:").pack(pady=5)

        selected_listbox = tk.Listbox(listbox_frame, height=15, width=40)
        selected_listbox.pack(fill="both", expand=True)

        # Store selected cells
        selected_cells = []

        # Function to handle cell selection
        def on_cell_click(event):
            # Identify the row and column of the clicked cell
            region = tree.identify("region", event.x, event.y)
            if region == "cell":
                row_id = tree.identify_row(event.y)  # Get row ID
                col_id = tree.identify_column(event.x)  # Get column ID (e.g., '#1')

                # Get actual column name
                col_index = int(col_id.strip("#")) - 1
                col_name = df.columns[col_index]

                # Get cell value
                row_index = tree.index(row_id)
                cell_value = df.iloc[row_index, col_index]

                # Toggle selection
                cell = (row_index, col_name)
                if cell in selected_cells:
                    selected_cells.remove(cell)  # Deselect if already selected
                    # Remove from Listbox
                    for i, item in enumerate(selected_listbox.get(0, tk.END)):
                        if item == f"Row {row_index + 1}, Column '{col_name}'":
                            selected_listbox.delete(i)
                            break
                else:
                    selected_cells.append(cell)  # Add to selection
                    # Add to Listbox
                    selected_listbox.insert(tk.END, f"Row {row_index + 1}, Column '{col_name}'")

        # Bind click event
        tree.bind("<Button-1>", on_cell_click)

        # Add encryption button
        def encrypt_selected_cells():
            """
            Encrypts the user-selected cells in the Excel file.
            """
            if not selected_cells:
                messagebox.showerror("Error", "No cells selected for encryption.")
                return

            try:
                # Generate an AES key (replace with secure key management if required)
                aes_key = os.urandom(16)

                # Encrypt the selected cells
                for row_index, col_name in selected_cells:
                    value = df.at[row_index, col_name]  # Get the cell value
                    if pd.notna(value):  # Only encrypt non-NaN values
                        try:
                            encrypted_value = encrypt_data(str(value), aes_key)  # Encrypt the cell value
                            df.at[row_index, col_name] = encrypted_value  # Update the DataFrame
                        except Exception as encryption_error:
                            messagebox.showwarning(
                                "Encryption Warning",
                                f"Failed to encrypt cell at Row {row_index + 1}, Column '{col_name}': {encryption_error}"
                            )

                # Save the updated file
                updated_file_path = filedialog.asksaveasfilename(
                    defaultextension=".xlsx",
                    filetypes=[("Excel files", "*.xlsx")],
                    title="Save Encrypted Excel File"
                )
                if not updated_file_path:
                    messagebox.showerror("Error", "File save operation was canceled.")
                    return

                # Save the DataFrame to the specified file path
                df.to_excel(updated_file_path, index=False)

                # Save the AES key as a separate file
                aes_key_file_path = os.path.splitext(updated_file_path)[0] + "_aes_key.bin"
                with open(aes_key_file_path, "wb") as aes_file:
                    aes_file.write(aes_key)

                # Show success message
                messagebox.showinfo(
                    "Success",
                    f"Encrypted Excel file saved to:\n{updated_file_path}\nAES key saved to:\n{aes_key_file_path}"
                )

                # Log the activity (if a logging function exists)
                log_file_activity(
                    user_id=current_user_id,
                    user_email=current_user_email,
                    department=current_user_department,
                    filename=os.path.basename(updated_file_path),
                    file_size=os.path.getsize(updated_file_path),
                    activity_type="Cell Encryption",
                    key=base64.b64encode(aes_key).decode('utf-8')
                )

            except Exception as e:
                messagebox.showerror("Error", f"Encryption failed: {e}")



        tk.Button(
            listbox_frame,
            text="Encrypt Selected Cells",
            command=encrypt_selected_cells
        ).pack(pady=10)

    except Exception as e:
        messagebox.showerror("Error", f"Failed to load Excel file: {e}")


def display_word_content(file_path, parent_frame):
    from docx import Document

    try:
        # Load Word document
        doc = Document(file_path)
        text_widget = tk.Text(parent_frame, wrap="word")
        text_widget.pack(fill="both", expand=True)

        # Insert document text into the Text widget
        for para in doc.paragraphs:
            text_widget.insert("end", para.text + "\n")

        # Add encryption button
        tk.Button(
            parent_frame,
            text="Encrypt Selected Text",
            command=lambda: encrypt_selected_text(text_widget, file_path)
        ).pack(pady=10)

    except Exception as e:
        messagebox.showerror("Error", f"Failed to load Word file: {e}")

def encrypt_selected_text(text_widget, file_path):
    from docx import Document
    from cryptography.fernet import Fernet

    selected_text = text_widget.selection_get()
    if not selected_text:
        messagebox.showerror("Error", "Please highlight text to encrypt.")
        return

    key = Fernet.generate_key()
    cipher = Fernet(key)
    encrypted_text = cipher.encrypt(selected_text.encode()).decode()

    # Modify the Word file (or a copy)
    doc = Document(file_path)
    for para in doc.paragraphs:
        para.text = para.text.replace(selected_text, encrypted_text)

    updated_file_path = filedialog.asksaveasfilename(defaultextension=".docx", filetypes=[("Word documents", "*.docx")])
    if updated_file_path:
        doc.save(updated_file_path)
        messagebox.showinfo("Success", f"Encrypted Word file saved at {updated_file_path}")





def encrypt_data():
    try:
        if not file_path:
            messagebox.showerror("Error", "Please upload an Excel file first.")
            return

        # Load RSA public key
        public_key, _ = load_rsa_keys()

        # Load the Excel file into a DataFrame
        df = pd.read_excel(file_path)

        # Prompt the user to select columns for encryption
        selected_columns = simpledialog.askstring(
            "Select Columns",
            "Enter the column names to encrypt, separated by commas (e.g., 'MSISDN, Name')"
        )
        if not selected_columns:
            messagebox.showerror("Error", "No columns selected for encryption.")
            return

        # Validate and split column names
        selected_columns = [col.strip() for col in selected_columns.split(",")]
        missing_columns = [col for col in selected_columns if col not in df.columns]
        if missing_columns:
            messagebox.showerror("Error", f"Column(s) not found: {', '.join(missing_columns)}")
            return

        # Generate AES key
        aes_key = os.urandom(16)

        # Encrypt AES key using the RSA public key
        cipher_rsa = PKCS1_OAEP.new(public_key)
        encrypted_aes_key = cipher_rsa.encrypt(aes_key)

        # Save the encrypted AES key alongside the encrypted file
        encrypted_file_path = filedialog.asksaveasfilename(
            defaultextension=".xlsx",
            filetypes=[("Excel files", "*.xlsx")],
            title="Save Encrypted Excel File"
        )
        if not encrypted_file_path:
            messagebox.showerror("Error", "File save operation was canceled.")
            return

        aes_key_file = os.path.splitext(encrypted_file_path)[0] + "_aes_key.bin"
        with open(aes_key_file, 'wb') as f:
            f.write(encrypted_aes_key)

        # Encrypt cell data
        for col in selected_columns:
            df[col] = df[col].astype(str).apply(lambda x: encrypt_data(x, aes_key))

        # Save the encrypted DataFrame to a file
        df.to_excel(encrypted_file_path, index=False)

        # Provide feedback to the user
        messagebox.showinfo(
            "Success",
            f"Data encrypted and saved to:\n{encrypted_file_path}\nAES key saved to:\n{aes_key_file}"
        )

        # Log the file activity into the database
        log_file_activity(
            user_id=current_user_id,
            user_email=current_user_email,
            department=current_user_department,
            filename=os.path.basename(encrypted_file_path),
            file_size=os.path.getsize(encrypted_file_path),
            activity_type="Encryption",
            key=base64.b64encode(aes_key).decode('utf-8')
        )

    except Exception as e:
        messagebox.showerror("Error", f"Encryption failed: {e}")








def decrypt_data():
    try:
        # 1. Make sure a file is selected
        if not file_path:
            messagebox.showerror("Error", "Please upload an encrypted Excel file first.")
            return

        # 2. Convert file path to base name and check for an approved request
        filename_only = os.path.basename(file_path)  # e.g., "data_encrypted.xlsx"

       

        conn = sqlite3.connect('ooredoo.db')
        cursor = conn.cursor()
        cursor.execute("""
            SELECT status 
            FROM key_requests
            WHERE user_id = ?
              AND file_name = ?
            ORDER BY request_id DESC
            LIMIT 1
        """, (current_user_id, filename_only))
        row = cursor.fetchone()
        conn.close()

        if not row or row[0] != 'APPROVED':
            messagebox.showerror("Error", "You do not have an approved request to decrypt this file.")
            return

        # 3. Determine the associated AES key file path
        key_file_path = os.path.splitext(file_path)[0] + "_aes_key.bin"
        if not os.path.exists(key_file_path):
            messagebox.showerror("Error", f"AES key file not found for {os.path.basename(file_path)}.")
            return

        # 4. Load the private RSA key
        with open('private.pem', 'rb') as f:
            private_key = RSA.import_key(f.read())

        # 5. Decrypt the AES key with RSA
        with open(key_file_path, 'rb') as f:
            encrypted_aes_key = f.read()
        cipher_rsa = PKCS1_OAEP.new(private_key)
        aes_key = cipher_rsa.decrypt(encrypted_aes_key)

        # 6. Load the encrypted Excel data
        df = pd.read_excel(file_path)

        # 7. Check if 'Encrypted_MSISDN' column is present
        if 'Encrypted_MSISDN' not in df.columns:
            messagebox.showerror("Error", "'Encrypted_MSISDN' column not found in the Excel file.")
            return

        # 8. Function to decrypt each MSISDN value
        def decrypt_msisdn(enc_msisdn, key):
            data = base64.b64decode(enc_msisdn)
            nonce, tag, ciphertext = data[:16], data[16:32], data[32:]
            cipher_aes = AES.new(key, AES.MODE_EAX, nonce=nonce)
            return cipher_aes.decrypt_and_verify(ciphertext, tag).decode('utf-8')

        # 9. Create a 'MSISDN' column by decrypting the existing 'Encrypted_MSISDN' values
        df['MSISDN'] = df['Encrypted_MSISDN'].apply(lambda enc: decrypt_msisdn(enc, aes_key))

        # 10. Remove the 'Encrypted_MSISDN' column
        df.drop(columns=['Encrypted_MSISDN'], inplace=True)

        # 11. Ask user where to save the decrypted file
        decrypted_file_path = filedialog.asksaveasfilename(
            defaultextension=".xlsx", 
            filetypes=[("Excel files", "*.xlsx")]
        )
        if not decrypted_file_path:
            messagebox.showerror("Error", "Please specify a valid file path to save the decrypted data.")
            return

        df.to_excel(decrypted_file_path, index=False)

        # 12. Indicate success
        messagebox.showinfo("Success", f"Data decrypted and saved to {decrypted_file_path}")

        # 13. Mark the request as acknowledged (ack_received=1)
        conn = sqlite3.connect('ooredoo.db')
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE key_requests
            SET ack_received = 1,
                ack_timestamp = datetime('now')
            WHERE user_id = ?
              AND file_name = ?
              AND status = 'APPROVED'
        """, (current_user_id, filename_only))
        conn.commit()
        conn.close()

        # 14. Log the file activity (using user_id, user_email, etc.)
        log_file_activity(
            user_id=current_user_id,
            user_email=current_user_email,  # or pass something else if you prefer
            department=current_user_department,
            filename=os.path.basename(decrypted_file_path),
            file_size=os.path.getsize(decrypted_file_path),
            activity_type="Decryption",
            key=base64.b64encode(aes_key).decode('utf-8')
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

    # Fetch all users, including user_id, first_name, last_name, and email
    users = get_all_users()  # This should return a list of dicts like [{"user_id": 1, "first_name": ..., ...}, ...]

    # Updated columns to include user_id
    columns = ('user_id', 'first_name', 'last_name', 'email')
    
    # Prepare row data for the Tableview
    row_data = []
    for user in users:
        row_data.append((
            user['user_id'],
            user['first_name'],
            user['last_name'],
            user['email']
        ))

    user_table = Tableview(
        master=user_frame,
        coldata=columns,
        rowdata=row_data,
        bootstyle="info"
    )
    user_table.pack(pady=10, fill='both', expand=True)

    # Button to remove users
    tb.Button(
        user_frame,
        text="Remove Selected User",
        command=lambda: remove_selected_user(user_table),
        bootstyle="danger-outline"
    ).pack(pady=10)

    # Return button to go back to the dashboard
    tb.Button(
        user_frame,
        text="Return",
        command=show_dashboard,
        bootstyle="secondary-outline"
    ).pack(pady=10)

def remove_user(user_id):
    """
    Deletes a user from the 'users' table using the user's numeric ID.
    
    :param user_id: The auto-incremented ID of the user to be removed.
    """
    try:
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        
        # Delete the user by user_id
        cursor.execute("DELETE FROM users WHERE user_id = ?", (user_id,))
        conn.commit()
        conn.close()

        # Optionally, refresh or return to the dashboard after removal
        show_dashboard()

    except Exception as e:
        messagebox.showerror("Error", f"Failed to remove user with ID {user_id}. Details: {e}")


def remove_selected_user(table):
    # Get the selected row; each row is a tuple of (user_id, first_name, last_name, email)
    selected = table.get_selected()
    if selected:
        # user_id is in the first column (index 0) after the update
        selected_user_id = selected[0][0]
        remove_user(selected_user_id)  # Updated remove_user to accept user_id
        messagebox.showinfo("Success", f"User with ID {selected_user_id} has been removed.")
    else:
        messagebox.showerror("Error", "No user selected.")


def manage_key_requests_window():
    req_win = tk.Toplevel()
    req_win.title("Key Requests")

    tree = ttk.Treeview(req_win, columns=("ReqID","UserID","File","Reason","Status","Time"), show="headings")
    tree.heading("ReqID", text="Request ID")
    tree.heading("UserID", text="User ID")
    tree.heading("File", text="File Name")
    tree.heading("Reason", text="Reason")
    tree.heading("Status", text="Status")
    tree.heading("Time", text="Request Time")
    tree.pack(fill="both", expand=True)

    def refresh_requests():
        tree.delete(*tree.get_children())
        conn = sqlite3.connect("ooredoo.db")
        cursor = conn.cursor()
        cursor.execute("""
            SELECT request_id, user_id, file_name, request_reason, status, request_timestamp
            FROM key_requests
            WHERE status='PENDING'
        """)
        rows = cursor.fetchall()
        conn.close()
        for row in rows:
            tree.insert("", tk.END, values=row)

    def approve_request():
        selected = tree.selection()
        if not selected:
            return
        values = tree.item(selected[0])["values"]
        request_id = values[0]

        conn = sqlite3.connect("ooredoo.db")
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE key_requests
            SET status='APPROVED', admin_id=?, approval_timestamp=datetime('now')
            WHERE request_id=?
        """, (current_admin_id, request_id))  # admin_id is the logged-in admin
        conn.commit()
        conn.close()

        messagebox.showinfo("Info", f"Request {request_id} approved.")
        refresh_requests()

    def reject_request():
        selected = tree.selection()
        if not selected:
            return
        values = tree.item(selected[0])["values"]
        request_id = values[0]

        conn = sqlite3.connect("ooredoo.db")
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE key_requests
            SET status='REJECTED', admin_id=?, approval_timestamp=datetime('now')
            WHERE request_id=?
        """, (current_admin_id, request_id))
        conn.commit()
        conn.close()

        messagebox.showinfo("Info", f"Request {request_id} rejected.")
        refresh_requests()

    btn_frame = tk.Frame(req_win)
    btn_frame.pack(pady=5)
    approve_btn = tk.Button(btn_frame, text="Approve", command=approve_request)
    reject_btn = tk.Button(btn_frame, text="Reject", command=reject_request)
    approve_btn.grid(row=0, column=0, padx=5)
    reject_btn.grid(row=0, column=1, padx=5)
     # Add a "Return" button
    def return_to_dashboard():
        req_win.destroy()  # Close the current window
        show_dashboard()   # Redirect to the admin dashboard

    return_btn = tk.Button(
        req_win,
        text="Return",
        command=return_to_dashboard
    )
    return_btn.pack(pady=10)
    
    refresh_requests()


def show_dashboard():
    global current_user_department, last_page

    # Check if the logged-in user is admin
    if current_user_department != 'Admin':
        messagebox.showerror("Access Denied", "Only admins can access the dashboard.")
        return

    # Clear previous frame
    for widget in root.winfo_children():
        widget.destroy()

    dashboard_frame = tb.Frame(root, padding=(20, 10), bootstyle="secondary")
    dashboard_frame.pack(fill="both", expand=True)

    # Title for the dashboard
    tb.Label(
        dashboard_frame, 
        text="Admin Dashboard - File Activities", 
        bootstyle="info", 
        font=("Arial", 18, "bold")
    ).pack(pady=10)

    try:
        # Fetch file activities from the database
        conn = sqlite3.connect('app_data.db')
        cursor = conn.cursor()
        # Now also select user_id from file_activities if it exists
        cursor.execute("""
            SELECT 
                user_id, 
                user_email, 
                department, 
                filename, 
                file_size, 
                timestamp, 
                activity_type,
                key 
                
            FROM file_activities
        """)
        file_activities = cursor.fetchall()

        # Process keys to obfuscate them for security (show only last 4 chars if length >= 4)
        # We'll also keep user_id in the row data so we can display it
        processed_activities = []
        for uid, email, dept, fname, fsize, ts,  activity,key in file_activities:
            if key and len(key) >= 4:
                obfuscated_key = f"******{key[-4:]}"
            else:
                obfuscated_key = "N/A"
            processed_activities.append((
                uid,
                email,
                dept,
                fname,
                fsize,
                ts,
                activity,
                obfuscated_key,
            ))

    except Exception as e:
        messagebox.showerror("Database Error", f"Failed to fetch file activities: {e}")
        return
    finally:
        if conn:
            conn.close()

    # Table Columns (now includes 'User ID')
    columns = (
        'User ID', 
        'User Email', 
        'Department', 
        'File Name', 
        'File Size (Bytes)', 
        'Timestamp', 
        
        'Activity Type',
        'Key'
    )

    # Create TableView
    file_table = Tableview(
        master=dashboard_frame,
        coldata=columns,
        rowdata=processed_activities,
        paginated=True,
        searchable=True,
        bootstyle="success"
    )
    file_table.pack(pady=10, fill='both', expand=True)

    # View All Users button
    tb.Button(
        dashboard_frame, 
        text="View All Users", 
        command=view_all_users, 
        bootstyle="secondary-outline"
    ).pack(pady=10)

    # Key Management button
    tb.Button(
        dashboard_frame,
        text="Key Management",
        command=open_key_management_window,
        bootstyle="warning-outline"
    ).pack(pady=10)

    # Manage Key Requests button (admin feature)
    manage_requests_button = tk.Button(dashboard_frame, text="Manage Key Requests", command=manage_key_requests_window)
    manage_requests_button.pack(pady=10)

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


# Fetch all users from SQLite (unchanged, except your final code might include user_id as well)
def get_all_users():
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute("SELECT first_name, last_name, email FROM users")
    users = cursor.fetchall()


# Call init_db() when the app starts to ensure the database is ready
init_db()


def create_main_page(is_encryption=True):
    global current_user_department, last_page

    # Set last_page based on the current mode
    last_page = "encryption" if is_encryption else "decryption"

    # Clear previous widgets
    for widget in root.winfo_children():
        widget.destroy()

    # Create the main frame
    main_frame = tb.Frame(root, padding=(20, 10), bootstyle="white")
    main_frame.pack(fill="both", expand=True)

    # Add the app logo
    add_logo(main_frame)

    # Buttons for encryption mode
    if is_encryption:
        tb.Button(main_frame, text="Upload Excel File", command=upload_file, style="SmallRedButton.TButton").pack(pady=10)
        
        tb.Button(main_frame, text="Simulate Cloud Upload", command=simulate_upload, style="SmallRedButton.TButton").pack(pady=10)
        tb.Button(main_frame,text="Encrypt Sensitive Data in Documents",command=open_document_encryption_tool,style="SmallRedButton.TButton").pack(pady=10)

    else:
        # Buttons for decryption mode
        tb.Button(main_frame, text="Simulate Cloud Download", command=simulate_upload, style="SmallRedButton.TButton").pack(pady=10)
        tb.Button(main_frame, text="Request Data Access", command=lambda: request_access_window(current_user_id), style="SmallRedButton.TButton").pack(pady=10)
        tb.Button(main_frame, text="Upload Excel File", command=upload_file, style="SmallRedButton.TButton").pack(pady=10)
        tb.Button(main_frame, text="Decrypt Data", command=decrypt_data, style="SmallRedButton.TButton").pack(pady=10)

    # Add Admin Dashboard button for admins
    if current_user_department == 'Admin':
        tb.Button(main_frame, text="Admin Dashboard", command=show_dashboard, style="SmallRedButton.TButton").pack(pady=10)

    # Add Sign Out button
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

# Global variables at module-level
current_user_id = None
current_admin_id = None
current_user_department = None
current_user_email = None


def submit_signin():
    global current_user_id, current_admin_id, current_user_department, current_user_email

    email = entry_email.get().strip()
    password = entry_password.get().strip()
    hashed_password = hash_password(password)

    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('SELECT user_id, password, department FROM users WHERE email = ?', (email,))
    result = cursor.fetchone()
    conn.close()

    if result:
        db_user_id, db_password, db_department = result
        if db_password == hashed_password:
            if db_department.lower() == 'admin':
                current_admin_id = db_user_id
                current_user_id = db_user_id
                current_user_department = db_department
                current_user_email = email
                messagebox.showinfo("Success", "Admin login successful!")
            else:
                current_user_id = db_user_id
                current_user_department = db_department
                current_user_email = email
                messagebox.showinfo("Success", "Sign-in successful!")
            
            create_operation_choice_page()  # proceed to next screen
        else:
            messagebox.showerror("Error", "Invalid email or password.")
    else:
        messagebox.showerror("Error", "Invalid email or password.")




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





# Start with the sign-in page
create_signin_page()

root.mainloop()

