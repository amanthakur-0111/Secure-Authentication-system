# gui_auth.py

import tkinter as tk
from tkinter import messagebox
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base
import bcrypt

# --- Database Setup (Same as before) ---
Base = declarative_base()

class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    email = Column(String(120), unique=True, nullable=False)
    password_hash = Column(String(60), nullable=False)

engine = create_engine("sqlite:///users.db")
Base.metadata.create_all(engine)
Session = sessionmaker(bind=engine)
session = Session()

# --- Password Hashing Functions (Same as before) ---
def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

def check_password(hashed_password, user_password):
    return bcrypt.checkpw(user_password.encode('utf-8'), hashed_password)

# --- GUI Application ---

class AuthApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Login System")
        self.root.geometry("400x300")
        
        # This will hold the currently logged-in user
        self.current_user = None

        self.show_login_window()

    def clear_window(self):
        """Clears all widgets from the root window."""
        for widget in self.root.winfo_children():
            widget.destroy()

    # --- Login Window ---
    def show_login_window(self):
        self.clear_window()
        self.root.title("Login")
        
        tk.Label(self.root, text="Email:", font=('Arial', 12)).pack(pady=5)
        self.email_entry = tk.Entry(self.root, width=30, font=('Arial', 12))
        self.email_entry.pack(pady=5)

        tk.Label(self.root, text="Password:", font=('Arial', 12)).pack(pady=5)
        self.password_entry = tk.Entry(self.root, show="*", width=30, font=('Arial', 12))
        self.password_entry.pack(pady=5)

        tk.Button(self.root, text="Login", command=self.handle_login, font=('Arial', 12), width=15).pack(pady=10)
        tk.Button(self.root, text="Go to Register", command=self.show_register_window, font=('Arial', 12), width=15).pack(pady=5)

    def handle_login(self):
        email = self.email_entry.get()
        password = self.password_entry.get()

        user = session.query(User).filter_by(email=email).first()

        if user and check_password(user.password_hash, password):
            self.current_user = user
            messagebox.showinfo("Success", f"Welcome back, {self.current_user.email}!")
            self.show_dashboard_window()
        else:
            messagebox.showerror("Error", "Invalid email or password.")

    # --- Registration Window ---
    def show_register_window(self):
        self.clear_window()
        self.root.title("Register")

        tk.Label(self.root, text="Email:", font=('Arial', 12)).pack(pady=5)
        self.reg_email_entry = tk.Entry(self.root, width=30, font=('Arial', 12))
        self.reg_email_entry.pack(pady=5)

        tk.Label(self.root, text="Password:", font=('Arial', 12)).pack(pady=5)
        self.reg_password_entry = tk.Entry(self.root, show="*", width=30, font=('Arial', 12))
        self.reg_password_entry.pack(pady=5)
        
        tk.Button(self.root, text="Register", command=self.handle_register, font=('Arial', 12), width=15).pack(pady=10)
        tk.Button(self.root, text="Back to Login", command=self.show_login_window, font=('Arial', 12), width=15).pack(pady=5)
        
    def handle_register(self):
        email = self.reg_email_entry.get()
        password = self.reg_password_entry.get()

        if session.query(User).filter_by(email=email).first():
            messagebox.showerror("Error", "An account with this email already exists.")
            return

        hashed = hash_password(password)
        new_user = User(email=email, password_hash=hashed)
        session.add(new_user)
        session.commit()
        
        messagebox.showinfo("Success", "Account created successfully! Please log in.")
        self.show_login_window()

    # --- Dashboard Window ---
    def show_dashboard_window(self):
        self.clear_window()
        self.root.title("Dashboard")

        welcome_message = f"Welcome to the Dashboard, {self.current_user.email}! ✨"
        tk.Label(self.root, text=welcome_message, font=('Arial', 14)).pack(pady=40)
        tk.Button(self.root, text="Logout", command=self.handle_logout, font=('Arial', 12), width=15).pack(pady=10)

    def handle_logout(self):
        self.current_user = None
        messagebox.showinfo("Logout", "You have been successfully logged out.")
        self.show_login_window()


if __name__ == "__main__":
    # Create the main window
    root = tk.Tk()
    # Create an instance of the app
    app = AuthApp(root)
    # Start the GUI event loop
    root.mainloop()