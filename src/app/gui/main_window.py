import tkinter as tk
from tkinter import font
import os
import sys

# Add the parent directory to the path to import from core
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.protection import PrivanaProtection
from core.endpoint_check import EndpointChecker
from .styles import *

class PrivanaMainWindow:
    def __init__(self, root):
        self.root = root
        self.root.title("Privana")
        self.root.geometry(f"{WINDOW_WIDTH}x{WINDOW_HEIGHT}")
        self.root.configure(bg=BACKGROUND_COLOR)
        self.root.resizable(False, False)
        
        # Initialize protection module
        self.protection = PrivanaProtection()
        
        # Create UI elements
        self.create_widgets()
        
        # Check protection status on load
        self.update_status()
    
    def create_widgets(self):
        # Logo frame
        self.logo_frame = tk.Frame(self.root, bg=BACKGROUND_COLOR)
        self.logo_frame.pack(pady=20)
        
        # Logo (using text emoji for now)
        self.logo_label = tk.Label(
            self.logo_frame, 
            text="🛡️",
            font=("Arial", 48),
            bg=BACKGROUND_COLOR
        )
        self.logo_label.pack()
        
        # App name
        self.name_label = tk.Label(
            self.logo_frame,
            text="PRIVANA",
            font=TITLE_FONT,
            bg=BACKGROUND_COLOR,
            fg=PRIMARY_COLOR
        )
        self.name_label.pack()
        
        # Greeting
        self.greeting_label = tk.Label(
            self.root,
            text="Hello, Walter",
            font=GREETING_FONT,
            bg=BACKGROUND_COLOR,
            fg=TEXT_DARK
        )
        self.greeting_label.pack(pady=10)
        
        # Protection button
        self.protection_button = tk.Button(
            self.root,
            text="Tap to Protect",
            font=BUTTON_FONT,
            width=BUTTON_WIDTH,
            height=BUTTON_HEIGHT,
            bg=BUTTON_NEUTRAL,
            fg="white",
            relief=tk.FLAT,
            bd=0,
            command=self.toggle_protection
        )
        self.protection_button.pack(pady=30)
        
        # Status text
        self.status_text = tk.Label(
            self.root,
            text="Status: Unprotected",
            font=STATUS_FONT,
            bg=BACKGROUND_COLOR,
            fg=TEXT_GRAY
        )
        self.status_text.pack()
    
    def toggle_protection(self):
        # Disable button during operation
        self.protection_button.config(state=tk.DISABLED)
        
        # Update UI to show connecting state
        self.protection_button.config(text="Connecting...")
        self.status_text.config(text="Status: Establishing your private road")
        
        # Start operation in a separate thread to avoid freezing the UI
        import threading
        threading.Thread(target=self._toggle_protection_thread, daemon=True).start()
    
    def _toggle_protection_thread(self):
        try:
            if self.protection.is_connected():
                # Disconnect if currently connected
                self.protection.disconnect()
                self.root.after(0, self.set_unprotected_state)
            else:
                # Check endpoint integrity before connecting
                checker = EndpointChecker()
                if not checker.check():
                    self.root.after(0, self.set_error_state, "Unsupported operating system for Privana")
                    return
                
                # Connect if not connected
                self.protection.connect()
                self.root.after(0, self.set_protected_state)
        except Exception as e:
            self.root.after(0, self.set_error_state, str(e))
        finally:
            # Re-enable button
            self.root.after(0, lambda: self.protection_button.config(state=tk.NORMAL))
    
    def set_protected_state(self):
        self.protection_button.config(text="You Are Protected", bg=BUTTON_PROTECTED)
        self.status_text.config(text="Status: Your internet is now private", fg=TEXT_GREEN)
    
    def set_unprotected_state(self):
        self.protection_button.config(text="Tap to Protect", bg=BUTTON_NEUTRAL)
        self.status_text.config(text="Status: Unprotected", fg=TEXT_GRAY)
    
    def set_error_state(self, error_message):
        self.protection_button.config(text="Try Again", bg="#ff9800")  # Gentle orange
        self.status_text.config(text=f"Status: {error_message}", fg="#d32f2f")  # Soft red
    
    def update_status(self):
        # Check current protection status
        if self.protection.is_connected():
            self.set_protected_state()
        else:
            self.set_unprotected_state()