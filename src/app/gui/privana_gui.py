import tkinter as tk
from .main_window import PrivanaMainWindow

def run_gui():
    root = tk.Tk()
    app = PrivanaMainWindow(root)
    root.mainloop()

if __name__ == "__main__":
    run_gui()