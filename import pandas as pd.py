import ttkbootstrap as tb
from ttkbootstrap.constants import *
from tkinter import messagebox, filedialog, ttk
from PIL import Image, ImageTk  # Requires the 'Pillow' library
import pandas as pd
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
import base64
import os
import csv
import datetime

# Global variables
file_path = ""
files_data = []  # To store file information
current_user_department = ""

# Load RSA keys
def load_rsa_keys():
    with open("public.pem", "rb") as pub_file:
        public_key = RSA.import_key(pub_file.read())
    with open("private.pem", "rb") as priv_file:
        private_key = RSA.import_key(priv_file.read())
    return public_key, private_key

# Hybrid encryption function (AES + RSA) with Base64 encoding for shorter ciphertext
def encrypt_msisdn(msisdn, aes_key, rsa_public_key):
    cipher_aes = AES.new(aes_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(msisdn.encode('utf-8'))
    cipher_rsa = PKCS1_OAEP.new(rsa_public_key)
    encrypted_aes_key = cipher_rsa.encrypt(aes_key)
    
    encrypted_data = encrypted_aes_key + cipher_aes.nonce + tag + ciphertext
    return base64.b64encode(encrypted_data).decode('utf-8')

# Add the Ooredoo logo and title
def add_logo(frame):
    try:
        logo_img = Image.open(r"C:\Users\youss\ooredoo_logo.png")
        logo_img = logo_img.resize((200, 50), Image.LANCZOS)
        logo_photo = ImageTk.PhotoImage(logo_img)
        logo_label = tb.Label(frame, image=logo_photo, background='white')
        logo_label.image = logo_photo
        logo_label.pack(pady=10)

        title_label = tb.Label(frame, text="ENCRYPTION APP", font=("Helvetica", 20, "bold"), bootstyle="danger")
        title_label.pack(pady=5)
    except Exception as e:
        print(f"Error loading logo: {e}")

# Create the main page (post sign-in)
def create_main_page():
    for widget in root.winfo_children():
        widget.destroy()
    
    main_frame = tb.Frame(root, padding=(20, 10), bootstyle="secondary")
    main_frame.pack(fill="both", expand=True)

    add_logo(main_frame)

    tb.Button(main_frame, text="Upload Excel File", command=upload_file, bootstyle="primary").pack(pady=10)
    tb.Button(main_frame, text="Encrypt Data", command=encrypt_data, bootstyle="success").pack(pady=10)
    tb.Button(main_frame, text="Simulate Cloud Upload", command=simulate_upload, bootstyle="warning").pack(pady=10)
    tb.Button(main_frame, text="Admin Dashboard", command=show_dashboard, bootstyle="info").pack(pady=10)

    # Sign out button
    tb.Button(main_frame, text="Sign Out", command=create_signin_page, bootstyle="danger-outline").pack(side="top", anchor="nw", padx=10, pady=10)

# Create the sign-up page
def create_signup_page():
    for widget in root.winfo_children():
        widget.destroy()

    signup_frame = tb.Frame(root, padding=(20, 10), bootstyle="secondary")
    signup_frame.pack(fill="both", expand=True)

    add_logo(signup_frame)

    def submit_signup():
        first_name = entry_first_name.get()
        last_name = entry_last_name.get()
        email = entry_email.get()
        password = entry_password.get()
        confirm_password = entry_confirm_password.get()
        department = department_var.get()

        if not all([first_name, last_name, email, password, confirm_password]):
            messagebox.showerror("Error", "All fields must be filled in.")
            return

        if password != confirm_password:
            messagebox.showerror("Error", "Passwords do not match.")
            return

        with open("users.csv", mode="a", newline="") as file:
            writer = csv.writer(file)
            writer.writerow([email, password, first_name, last_name, department])

        messagebox.showinfo("Success", "User registered successfully!")
        create_signin_page()

    tb.Label(signup_frame, text="First Name:", bootstyle="info").pack(pady=5)
    entry_first_name = tb.Entry(signup_frame)
    entry_first_name.pack(pady=5)

    tb.Label(signup_frame, text="Last Name:", bootstyle="info").pack(pady=5)
    entry_last_name = tb.Entry(signup_frame)
    entry_last_name.pack(pady=5)

    tb.Label(signup_frame, text="Email:", bootstyle="info").pack(pady=5)
    entry_email = tb.Entry(signup_frame)
    entry_email.pack(pady=5)

    tb.Label(signup_frame, text="Password:", bootstyle="info").pack(pady=5)
    entry_password = tb.Entry(signup_frame, show="*")
    entry_password.pack(pady=5)

    tb.Label(signup_frame, text="Confirm Password:", bootstyle="info").pack(pady=5)
    entry_confirm_password = tb.Entry(signup_frame, show="*")
    entry_confirm_password.pack(pady=5)

    tb.Label(signup_frame, text="Department:", bootstyle="info").pack(pady=5)
    department_var = tb.StringVar(value="Marketing")
    departments = [("Marketing", "Marketing"), ("IT", "IT"), ("Infrastructure", "Infrastructure"), ("Admin", "Admin")]
    for text, value in departments:
        tb.Radiobutton(signup_frame, text=text, variable=department_var, value=value, bootstyle="danger-toolbutton").pack(anchor="w")

    tb.Button(signup_frame, text="Sign Up", command=submit_signup, bootstyle="success").pack(pady=20)

    # Return button to sign-in page
    tb.Button(signup_frame, text="Return", command=create_signin_page, bootstyle="secondary-outline").pack(side="top", anchor="nw", padx=10, pady=10)

# Create the sign-in page
def create_signin_page():
    for widget in root.winfo_children():
        widget.destroy()

    signin_frame = tb.Frame(root, padding=(20, 10), bootstyle="secondary")
    signin_frame.pack(fill="both", expand=True)

    add_logo(signin_frame)

    def submit_signin():
        email = entry_email.get()
        password = entry_password.get()

        with open("users.csv", mode="r") as file:
            reader = csv.reader(file)
            for row in reader:
                if row[0] == email and row[1] == password:
                    global current_user_department
                    current_user_department = row[4]
                    create_main_page()
                    return

        messagebox.showerror("Error", "Invalid credentials.")

    tb.Label(signin_frame, text="Email:", bootstyle="info").pack(pady=5)
    entry_email = tb.Entry(signin_frame)
    entry_email.pack(pady=5)

    tb.Label(signin_frame, text="Password:", bootstyle="info").pack(pady=5)
    entry_password = tb.Entry(signin_frame, show="*")
    entry_password.pack(pady=5)

    tb.Button(signin_frame, text="Sign In", command=submit_signin, bootstyle="primary").pack(pady=20)
    tb.Button(signin_frame, text="Sign Up", command=create_signup_page, bootstyle="secondary").pack(pady=10)

# Placeholder functions for file upload, encryption, and dashboard
def upload_file():
    global file_path
    file_path = filedialog.askopenfilename(filetypes=[("Excel files", "*.xlsx")])
    if file_path:
        messagebox.showinfo("File Selected", f"File selected: {file_path}")


# Function to handle encryption
def encrypt_data():
    try:
        if not file_path:
            messagebox.showerror("Error", "Please upload an Excel file first.")
            return

        public_key, private_key = load_rsa_keys()

        df = pd.read_excel(file_path)

        if 'MSISDN' not in df.columns:
            messagebox.showerror("Error", "'MSISDN' column not found in the Excel file.")
            return

        aes_key = os.urandom(16)
        df['Encrypted_MSISDN'] = df['MSISDN'].apply(lambda msisdn: encrypt_msisdn(str(msisdn), aes_key, public_key))

        encrypted_file_path = filedialog.asksaveasfilename(defaultextension=".xlsx", filetypes=[("Excel files", "*.xlsx")])
        if encrypted_file_path:
            df.to_excel(encrypted_file_path, index=False)
            messagebox.showinfo("Success", f"Data encrypted and saved to {encrypted_file_path}")

            # Record the file information for the dashboard
            file_info = {
                "department": current_user_department,
                "filename": os.path.basename(encrypted_file_path),
                "date": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "size": os.path.getsize(encrypted_file_path)
            }
            files_data.append(file_info)

    except Exception as e:
        messagebox.showerror("Error", str(e))

# Function to simulate cloud upload
def simulate_upload():
    messagebox.showinfo("Cloud Upload", "Simulated upload to cloud server completed!")

# Function to show the admin dashboard
def show_dashboard():
    if current_user_department == "Admin":
        dashboard_window = tb.Toplevel(root)
        dashboard_window.title("Admin Dashboard")
        dashboard_window.geometry("600x400")

        # Create the treeview to display file information
        tree = ttk.Treeview(dashboard_window, columns=("Department", "Filename", "Date", "Size"), show="headings")
        tree.heading("Department", text="Department")
        tree.heading("Filename", text="Filename")
        tree.heading("Date", text="Date")
        tree.heading("Size", text="Size (bytes)")

        # Insert the files data into the treeview
        for file_info in files_data:
            tree.insert("", "end", values=(file_info["department"], file_info["filename"], file_info["date"], file_info["size"]))

        tree.pack(fill=tb.BOTH, expand=True)
    else:
        messagebox.showerror("Error", "Only Admins can view the dashboard.")

# Create the main app window
root = tb.Window(themename="superhero")  # Choose a suitable theme
root.title("Ooredoo Encryption App")
root.geometry("500x600")

create_signin_page()

root.mainloop()
