import tkinter as tk
from tkcalendar import DateEntry

def test_datepicker():
    window = tk.Tk()
    window.title("Test Date Picker")

    date_entry = DateEntry(window, selectmode="day", date_pattern="yyyy-mm-dd")
    date_entry.pack(padx=20, pady=20)

    window.mainloop()

test_datepicker()
