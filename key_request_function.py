import tkinter as tk
from tkinter import messagebox
import sqlite3
import os
# Suppose you have a global or passed-in variable: current_user_id

def request_access_window(current_user_id):
    window = tk.Toplevel()
    window.title("Request Access")

    tk.Label(window, text="File/Data Name:").grid(row=0, column=0, padx=5, pady=5)
    file_name_var = tk.StringVar()
    file_name_entry = tk.Entry(window, textvariable=file_name_var, width=30)
    file_name_entry.grid(row=0, column=1, padx=5, pady=5)

    tk.Label(window, text="Reason (Optional):").grid(row=1, column=0, padx=5, pady=5)
    reason_text = tk.Text(window, height=5, width=30)
    reason_text.grid(row=1, column=1, padx=5, pady=5)

    def submit_request():
        try:
            # Retrieve the user-typed or path-based file name
            full_file_path = file_name_var.get().strip()
            reason = reason_text.get("1.0", "end-1c").strip()

            # If there's no input for file/data name, show error
            if not full_file_path:
                messagebox.showerror("Error", "Please enter a file or data name.")
                return

            # Convert the full path to just the base file name
            base_name = os.path.basename(full_file_path)

            # Debug print to see what's being inserted
            print(f"Debug: current_user_id={current_user_id}, file_name={base_name}, reason={reason}")

            conn = sqlite3.connect("ooredoo.db")
            cursor = conn.cursor()

            # Insert into the table with base_name instead of the full path
            cursor.execute("""
                INSERT INTO key_requests (user_id, file_name, request_reason, status)
                VALUES (?, ?, ?, 'PENDING')
            """, (current_user_id, base_name, reason))

            conn.commit()
            conn.close()

            messagebox.showinfo("Success", "Your access request has been submitted.")
            window.destroy()

        except Exception as e:
            messagebox.showerror("Error", f"Failed to submit request: {e}")


    submit_btn = tk.Button(window, text="Submit", command=submit_request)
    submit_btn.grid(row=2, column=1, pady=10, sticky="e")

    window.mainloop()

