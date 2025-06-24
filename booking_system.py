import tkinter as tk
from tkinter import messagebox
from PIL import ImageTk, Image
from time import strftime
import sqlite3
import tkinter.ttk as ttk
import datetime
import os
import random

# Database setup
connect = sqlite3.connect("booking_system.db")
cursor = connect.cursor()

# Create the users table
cursor.execute("""
CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY,
    password TEXT NOT NULL,
    role TEXT NOT NULL
)
""")

# Insert default users if they do not exist
cursor.execute("select * from users where username =?", ("Admin",))
if not cursor.fetchone():
    cursor.execute(
        "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
        ("Admin", "password1", "admin"))
cursor.execute("select * from users where username =?", ("Customer",))
if not cursor.fetchone():
    cursor.execute(
        "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
        ("Customer", "password2", "customer"))
connect.commit()

# Create the user_bookings table
cursor.execute("""
CREATE TABLE IF NOT EXISTS user_bookings (
    bookings TEXT PRIMARY KEY,
    update_stock INTEGER NOT NULL,
    stock_status TEXT NOT NULL
)
""")

# Pre-fill the database with fixed items and default stock of 10
fixed_items = [
    "rice", "beans", "maize", "phone", "laptop",
    "bulbs", "TV", "decorder", "curtain", "bed"
]
for item in fixed_items:
    cursor.execute("SELECT * FROM user_bookings WHERE bookings=?", (item,))
    if not cursor.fetchone():
        cursor.execute(
            "INSERT INTO user_bookings (bookings, update_stock, stock_status) VALUES (?, ?, ?)",
            (item, 10, "In Stock")
        )
connect.commit()

# Create the bookings_history table if it doesn't exist
cursor.execute("""
CREATE TABLE IF NOT EXISTS bookings_history (
    id TEXT PRIMARY KEY,
    username TEXT NOT NULL,
    item TEXT NOT NULL,
    quantity INTEGER NOT NULL,
    date_time TEXT NOT NULL
)
""")
connect.commit()

# Load logo image safely
logo_path = "image1.jpeg"
if os.path.exists(logo_path):
    logo = Image.open(logo_path)
else:
    logo = None

def show_popup_notification(parent, message, color="green"):
    notif = tk.Toplevel(parent)
    notif.title("Notification")
    notif.geometry("350x100")
    notif.configure(bg="white")
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    tk.Label(
        notif,
        text=f"{message}\n{now}",
        fg=color,
        bg="white",
        font=("Arial", 12, "bold")
    ).pack(expand=True, fill="both")
    notif.after(2000, notif.destroy)

def notify_low_stock(item):
    msg = f"Alert: Only 1 {item.title()} left in stock!"
    admin_notif = tk.Toplevel()
    admin_notif.title("Low Stock Alert (Admin)")
    admin_notif.geometry("350x100")
    admin_notif.configure(bg="yellow")
    tk.Label(
        admin_notif,
        text=msg,
        fg="red",
        bg="yellow",
        font=("Arial", 14, "bold")
    ).pack(expand=True, fill="both")
    admin_notif.after(3000, admin_notif.destroy)
    customer_notif = tk.Toplevel()
    customer_notif.title("Low Stock Alert (Customer)")
    customer_notif.geometry("350x100")
    customer_notif.configure(bg="yellow")
    tk.Label(
        customer_notif,
        text=msg,
        fg="red",
        bg="yellow",
        font=("Arial", 14, "bold")
    ).pack(expand=True, fill="both")
    customer_notif.after(3000, customer_notif.destroy)

def show_booked_successful_popup(parent):
    notif = tk.Toplevel(parent)
    notif.title("Success")
    notif.geometry("300x100")
    notif.configure(bg="white")
    tk.Label(
        notif,
        text="Booked successful",
        fg="green",
        bg="white",
        font=("Arial", 14, "bold")
    ).pack(expand=True, fill="both")
    notif.after(2000, notif.destroy)

def add_booking_history(username, item, quantity):
    booking_id = str(random.randint(100000, 999999))
    date_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute(
        "INSERT INTO bookings_history (id, username, item, quantity, date_time) VALUES (?, ?, ?, ?, ?)",
        (booking_id, username, item, quantity, date_time)
    )
    connect.commit()

def show_bookings_window(parent):
    bookings_window = tk.Toplevel(parent)
    bookings_window.title("Book an Item")
    bookings_window.geometry("400x550")
    bookings_window.configure(bg="white")

    tk.Label(bookings_window, text="Available Items for Booking", font=("Arial", 14, "bold"), bg="white").pack(pady=10)

    cursor.execute("SELECT bookings, update_stock, stock_status FROM user_bookings")
    items = cursor.fetchall()

    frame = tk.Frame(bookings_window, bg="white")
    frame.pack(fill=tk.BOTH, expand=True)

    canvas = tk.Canvas(frame, bg="white")
    scrollbar = tk.Scrollbar(frame, orient="vertical", command=canvas.yview)
    scrollable_frame = tk.Frame(canvas, bg="white")

    scrollable_frame.bind(
        "<Configure>",
        lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
    )

    canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
    canvas.configure(yscrollcommand=scrollbar.set)
    canvas.pack(side="left", fill="both", expand=True)
    scrollbar.pack(side="right", fill="y")

    for item, stock, status in items:
        tk.Label(
            scrollable_frame,
            text=f"{item.title()} - Stock: {stock} - Status: {status}",
            font=("Arial", 12),
            bg="white"
        ).pack(anchor="w", padx=10, pady=2)

    tk.Label(bookings_window, text="Who wants to book?", font=("Arial", 12, "bold"), bg="white").pack(pady=5)
    username_var = tk.StringVar()
    tk.Entry(bookings_window, textvariable=username_var, font=("Arial", 12)).pack(pady=5)

    tk.Label(bookings_window, text="Book an Item", font=("Arial", 12, "bold"), bg="white").pack(pady=10)
    item_names = [item[0] for item in items]
    item_var = tk.StringVar(value=item_names[0] if item_names else "")
    tk.OptionMenu(bookings_window, item_var, *item_names).pack(pady=5)

    tk.Label(bookings_window, text="Quantity:", bg="white").pack()
    qty_var = tk.IntVar(value=1)
    tk.Entry(bookings_window, textvariable=qty_var).pack(pady=5)

    def book_item():
        username = username_var.get().strip()
        item = item_var.get()
        qty = qty_var.get()
        if not username:
            messagebox.showerror("Error", "Please enter the username.", parent=bookings_window)
            return
        cursor.execute("SELECT update_stock FROM user_bookings WHERE bookings=?", (item,))
        stock = cursor.fetchone()
        if stock and stock[0] >= qty and qty > 0:
            new_stock = stock[0] - qty
            status = "In Stock" if new_stock > 0 else "Out of Stock"
            cursor.execute(
                "UPDATE user_bookings SET update_stock=?, stock_status=? WHERE bookings=?",
                (new_stock, status, item)
            )
            connect.commit()
            add_booking_history(username, item, qty)
            show_booked_successful_popup(bookings_window)
            if new_stock == 0:
                show_popup_notification(bookings_window, f"{item.title()} is currently out of stock!", "red")
            elif new_stock == 1:
                notify_low_stock(item)
            bookings_window.destroy()
            show_bookings_window(parent)
        else:
            messagebox.showerror("Error", "Not enough stock for this item or invalid quantity.", parent=bookings_window)

    tk.Button(
        bookings_window,
        text="Book Item",
        command=book_item,
        bg="green",
        fg="white",
        font=("Arial", 16, "bold"),
        height=2,
        width=20
    ).pack(pady=20)

def signup_window():
    signup = tk.Toplevel()
    signup.title("Sign Up")
    signup.geometry("400x400")
    signup.configure(bg="white")
    if logo:
        signup_logo = ImageTk.PhotoImage(logo)
        signup.iconphoto(False, signup_logo)
    
    tk.Label(
        signup,text="create a new account",
        font=("agency fb", 20, "bold"),
        bg="white", fg="black"
    ).pack(pady=10)
    
    tk.Label(signup, text="Username:", font=("agency fb", 12), bg="white").pack(pady=5)
    entry_username = tk.Entry(signup, font=("agency fb", 12))
    entry_username.pack()
    
    tk.Label(signup, text="Password:", font=("agency fb", 12), bg="white").pack()
    entry_password = tk.Entry(signup, show="*", font=("agency fb", 12))
    entry_password.pack()
    
    tk.Label(signup, text="confirm password:", font=("agency fb", 12), bg="white").pack()
    entry_confirm_password = tk.Entry(signup, show="*", font=("agency fb", 12))
    entry_confirm_password.pack()
    
    tk.Label(signup, text="Role:", font=("agency fb", 12), bg="white").pack()
    role_var = tk.StringVar(value="customer")
    role_menu = ttk.Combobox(
        signup, textvariable=role_var, values=["customer", "admin"], state="readonly"
    )
    role_menu.pack()
    
    def create_account():
        username = entry_username.get()
        password = entry_password.get()
        confirm_password = entry_confirm_password.get()
        role = role_var.get()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        if cursor.fetchone():
            messagebox.showerror("Error", "Username already exists",parent=signup)
        elif password != confirm_password:
            messagebox.showerror("Error", "Passwords do not match", parent=signup)
        elif not username or not password:
            messagebox.showerror("Error", "Username and password cannot be empty", parent=signup)
        else:
            cursor.execute(
                "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                (username, password, role)
            )
            connect.commit()
            messagebox.showinfo("Success", "Account created successfully", parent=signup)
            signup.destroy()
            
    tk.Button(
        signup,
        text="Create Account",
        font=("agency fb", 14),
        width=16,
        command=create_account,
        bg="indigo",
        fg="white",
        cursor="hand2",
        relief="flat"
    ).pack(pady=20)

def login_window():
    login = tk.Tk()
    login.title("Login")
    login.geometry("400x300")
    login.resizable(False, False)
    login.configure(bg="white")
    if logo:
        login_logo = ImageTk.PhotoImage(logo)
        login.iconphoto(False, login_logo)

    tk.Label(
        login,
        text="Store Booking Login",
        font=("agency fb", 20, "bold"),
        bg="white",
        fg="black",
    ).pack(pady=10)

    tk.Label(login, text="Username:", font=("agency fb", 12), bg="white").pack(pady=5)
    entry_username = tk.Entry(login, font=("agency fb", 12))
    entry_username.pack()

    tk.Label(login, text="Password:", font=("agency fb", 12), bg="white").pack(pady=5)
    entry_password = tk.Entry(login, show="*", font=("agency fb", 12))
    entry_password.pack()

    def authenticate():
        username = entry_username.get()
        password = entry_password.get()
        cursor.execute(
            "Select role FROM users WHERE username=? AND password=?", (username, password)
        )
        result = cursor.fetchone()
        if result:
            login.destroy()
            open_dashboard(username, result[0])
        else:
            messagebox.showerror("Login Failed", "Invalid username or password")

    tk.Button(
        login,
        text="Login",
        font=("agency fb", 14),
        width=15,
        command=authenticate,
        bg="indigo",
        fg="white",
        cursor="hand2",
        relief="flat"
    ).pack(pady=10)
    tk.Button(
        login,
        text="sign up",
        font=("agency fb", 14),
        width=15,
        command=signup_window,
        bg="indigo",
        fg="white",
        cursor="hand2",
        relief="flat"
    ).pack(pady=2)

    login.mainloop()

def show_update_stock_window(parent):
    update_window = tk.Toplevel(parent)
    update_window.title("Update Stock")
    update_window.geometry("400x400")
    update_window.configure(bg="white")

    tk.Label(update_window, text="Update Stock for Items", font=("Arial", 14, "bold"), bg="white").pack(pady=10)

    cursor.execute("SELECT bookings FROM user_bookings")
    items = [row[0] for row in cursor.fetchall()]
    item_var = tk.StringVar(value=items[0] if items else "")
    tk.OptionMenu(update_window, item_var, *items).pack(pady=5)

    tk.Label(update_window, text="Change in Stock (+/-):", bg="white").pack()
    qty_var = tk.IntVar(value=1)
    tk.Entry(update_window, textvariable=qty_var).pack(pady=5)

    def update_stock():
        item = item_var.get()
        change = qty_var.get()
        cursor.execute("SELECT update_stock FROM user_bookings WHERE bookings=?", (item,))
        stock = cursor.fetchone()
        if stock is not None:
            new_stock = max(stock[0] + change, 0)
            status = "In Stock" if new_stock > 0 else "Out of Stock"
            cursor.execute(
                "UPDATE user_bookings SET update_stock=?, stock_status=? WHERE bookings=?",
                (new_stock, status, item)
            )
            connect.commit()
            now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            show_popup_notification(update_window, f"{item.title()} stock updated at {now}", "blue")
            if new_stock == 1:
                notify_low_stock(item)
            update_window.destroy()
        else:
            messagebox.showerror("Error", "Item not found.")

    tk.Button(update_window, text="Update Stock", command=update_stock, bg="blue", fg="white").pack(pady=20)

def show_stock_status_window(parent):
    status_window = tk.Toplevel(parent)
    status_window.title("Stock Status")
    status_window.geometry("400x400")
    status_window.configure(bg="white")

    tk.Label(status_window, text="Current Stock Status", font=("Arial", 14, "bold"), bg="white").pack(pady=10)

    cursor.execute("SELECT bookings, update_stock, stock_status FROM user_bookings")
    items = cursor.fetchall()

    frame = tk.Frame(status_window, bg="white")
    frame.pack(fill=tk.BOTH, expand=True)

    canvas = tk.Canvas(frame, bg="white")
    scrollbar = tk.Scrollbar(frame, orient="vertical", command=canvas.yview)
    scrollable_frame = tk.Frame(canvas, bg="white")

    scrollable_frame.bind(
        "<Configure>",
        lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
    )

    canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
    canvas.configure(yscrollcommand=scrollbar.set)
    canvas.pack(side="left", fill="both", expand=True)
    scrollbar.pack(side="right", fill="y")

    for item, stock, status in items:
        tk.Label(
            scrollable_frame,
            text=f"{item.title()} - Stock: {stock} - Status: {status}",
            font=("Arial", 12),
            bg="white"
        ).pack(anchor="w", padx=10, pady=2)

def show_booking_history_window(parent, username, role):
    history_window = tk.Toplevel(parent)
    history_window.title("Booking History")
    history_window.geometry("700x400")
    history_window.configure(bg="white")

    tk.Label(history_window, text="Booking History", font=("Arial", 16, "bold"), bg="white").pack(pady=10)

    columns = ("date_time", "username", "id", "item", "quantity")
    tree = ttk.Treeview(history_window, columns=columns, show="headings", height=15)
    tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

    tree.heading("date_time", text="Time & Date")
    tree.heading("username", text="Username")
    tree.heading("id", text="Booking ID")
    tree.heading("item", text="Item")
    tree.heading("quantity", text="Quantity")

    tree.column("date_time", width=150)
    tree.column("username", width=120)
    tree.column("id", width=100)
    tree.column("item", width=120)
    tree.column("quantity", width=80)

    cursor.execute("SELECT date_time, username, id, item, quantity FROM bookings_history ORDER BY date_time DESC")
    records = cursor.fetchall()

    for row in records:
        tree.insert("", tk.END, values=row)

def open_dashboard(username, role):
    root = tk.Tk()
    root.title("STORE BOOKING SYSTEM")
    root.geometry("1270x668+0+0")
    root.resizable(False, False)
    root.config(bg="white")
    if logo:
        logos = ImageTk.PhotoImage(logo)
        root.iconphoto(False, logos)
    def logoutfunc():
        res = messagebox.askyesno("logout", "are you sure you want to logout?")
        if res:
            root.destroy()
            login_window()
        else:
            pass

    tk.Label(
        root,
        text="STORE BOOKING SYSTEM",
        font=("agency fb", 40, "bold"),
        bg="indigo",
        fg="white",
    ).place(x=0, y=0, relwidth=1)

    tk.Button(
        root,
        text="Logout",
        font=("agency fb", 20, "bold"),
        fg="indigo",
        command=logoutfunc,
        cursor="hand2"
    ).place(x=1110, y=6)

    def update_clock():
        current_time = strftime("%H:%M:%S %p")
        clock_label.config(text=current_time)
        clock_label.after(1000, update_clock)

    clock_label = tk.Label(
        root, font=("calibri", 35, "bold"), background="purple", foreground="white"
    )
    clock_label.pack(anchor="nw", padx=20, pady=4)
    update_clock()

    tk.Label(
        root,
        text=f"Welcome USER: {username} | with ROLE : {role}!",
        font=("agency fb", 15, "bold"),
        bg="grey",
        fg="white",
    ).place(x=0, y=70, relwidth=1)
    if role == "customer":
        left_frame = tk.Frame(root, bg="light grey")
        left_frame.place(x=0, y=100, width=200, height=545)

        tk.Label(
            left_frame, text="CUSTOMER'S UI", font=("agency fb", 25), bg="green", fg="white"
        ).pack(fill=tk.X)

        tk.Button(
            left_frame,
            text="BOOK AN ITEM",
            font=("agency fb", 20, "bold"),
            bg="light blue",
            fg="black",
            cursor="hand2",
            command=lambda: show_bookings_window(root)
        ).pack(fill=tk.X)
        tk.Button(
            left_frame,
            text="STOCK STATUS",
            font=("agency fb", 20, "bold"),
            bg="light blue",
            fg="black",
            cursor="hand2",
            command=lambda: show_stock_status_window(root)
        ).pack(fill=tk.X)
        tk.Button(
            left_frame,
            text="EXIT",
            font=("agency fb", 20, "bold"),
            bg="light blue",
            fg="black",
            cursor="hand2",
            command=root.destroy,
        ).pack(fill=tk.X)
    elif role == "admin":
        right_frame = tk.Frame(root, bg="light grey")
        right_frame.place(x=1070, y=102, width=200, height=555)

        tk.Label(
            right_frame, text="ADMIN UI", font=("agency fb", 20), bg="red", fg="white"
        ).pack(fill=tk.X)

        tk.Button(
            right_frame,
            text="BOOKINGS",
            font=("agency fb", 20, "bold"),
            bg="light blue",
            fg="black",
            cursor="hand2",
            command=lambda: show_bookings_window(root)
        ).pack(fill=tk.X)
        tk.Button(
            right_frame,
            text="UPDATE STOCK",
            font=("agency fb", 20, "bold"),
            bg="light blue",
            fg="black",
            cursor="hand2",
            command=lambda: show_update_stock_window(root)
        ).pack(fill=tk.X)
        tk.Button(
            right_frame,
            text="STOCK STATUS",
            font=("agency fb", 20, "bold"),
            bg="light blue",
            fg="black",
            cursor="hand2",
            command=lambda: show_stock_status_window(root)
        ).pack(fill=tk.X)
        tk.Button(
            right_frame,
            text="HISTORY",
            font=("agency fb", 20, "bold"),
            bg="light blue",
            fg="black",
            cursor="hand2",
            command=lambda: show_booking_history_window(root, username, role)
        ).pack(fill=tk.X)
        tk.Button(
            right_frame,
            text="EXIT",
            font=("agency fb", 20, "bold"),
            bg="light blue",
            fg="black",
            cursor="hand2",
            command=root.destroy,
        ).pack(fill=tk.X)

    root.mainloop()

# ---------- RUN LOGIN WINDOW ----------
login_window()