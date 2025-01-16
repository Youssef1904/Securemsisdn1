import tkinter as tk
from tkinter import messagebox
import sqlite3

# Suppose you have a global or passed-in variable: current_user_id

def request_access_window(current_user_id):
    window = tk.Toplevel()
    window.title("Request Access")

    tk.Label(window, text="File/Data Name:").grid(row=0, column=0, padx=5, pady=5)
    data_name_var = tk.StringVar()
    data_name_entry = tk.Entry(window, textvariable=data_name_var, width=30)
    data_name_entry.grid(row=0, column=1, padx=5, pady=5)

    tk.Label(window, text="Reason (Optional):").grid(row=1, column=0, padx=5, pady=5)
    reason_text = tk.Text(window, height=5, width=30)
    reason_text.grid(row=1, column=1, padx=5, pady=5)

    def submit_request():
        data_name = data_name_var.get()
        reason = reason_text.get("1.0", "end-1c").strip()
        if not data_name:
            messagebox.showerror("Error", "Please enter a file or data name.")
            return

        conn = sqlite3.connect("ooredoo.db")
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO key_requests (user_id, data_name, request_reason, status)
            VALUES (?, ?, ?, 'PENDING')
        """, (current_user_id, data_name, reason))
        conn.commit()
        conn.close()

        messagebox.showinfo("Success", "Your access request has been submitted.")
        window.destroy()

    submit_btn = tk.Button(window, text="Submit", command=submit_request)
    submit_btn.grid(row=2, column=1, pady=10, sticky="e")

    window.mainloop()
