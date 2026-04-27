import os
import hashlib
import time
import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter import ttk
from tkinterdnd2 import DND_FILES, TkinterDnD
from cryptography.fernet import Fernet
from base64 import urlsafe_b64encode
from hashlib import pbkdf2_hmac


# ---------- KEY GENERATION ----------

def generate_key(password):

    password = password.encode()
    salt = b"secure_salt"

    kdf = pbkdf2_hmac(
        "sha256",
        password,
        salt,
        100000
    )

    return urlsafe_b64encode(kdf)


# ---------- HASH ----------

def generate_hash(file_path):

    sha256 = hashlib.sha256()

    with open(file_path, "rb") as f:
        while chunk := f.read(4096):
            sha256.update(chunk)

    return sha256.hexdigest()


# ---------- PASSWORD STRENGTH ----------

def check_password_strength(event=None):

    password = password_entry.get()
    strength = 0

    if len(password) >= 8:
        strength += 1
    if any(c.isdigit() for c in password):
        strength += 1
    if any(c.isupper() for c in password):
        strength += 1
    if any(c in "!@#$%^&*" for c in password):
        strength += 1

    value = strength * 25
    strength_bar["value"] = value

    if value <= 25:
        strength_label.config(text="Weak", fg="red")
    elif value <= 50:
        strength_label.config(text="Medium", fg="orange")
    elif value <= 75:
        strength_label.config(text="Strong", fg="yellow")
    else:
        strength_label.config(text="Very Strong", fg="green")


# ---------- FILE SIZE ----------

def get_file_size(file_path):

    size = os.path.getsize(file_path)

    for unit in ['B','KB','MB','GB']:
        if size < 1024:
            return f"{size:.2f} {unit}"
        size /= 1024


# ---------- ENCRYPT ----------

def encrypt_file(file_path, password):

    key = generate_key(password)
    fernet = Fernet(key)

    with open(file_path, "rb") as file:
        data = file.read()

    encrypted = fernet.encrypt(data)

    encrypted_path = file_path + ".enc"

    with open(encrypted_path, "wb") as file:
        file.write(encrypted)

    file_hash = generate_hash(file_path)

    with open(encrypted_path + ".hash", "w") as h:
        h.write(file_hash)


# ---------- DECRYPT ----------

def decrypt_file(file_path, password):

    if not file_path.endswith(".enc"):
        messagebox.showerror("Error", "Select .enc file")
        return

    key = generate_key(password)
    fernet = Fernet(key)

    with open(file_path, "rb") as file:
        encrypted = file.read()

    decrypted = fernet.decrypt(encrypted)

    original = file_path.replace(".enc", "")

    with open(original, "wb") as file:
        file.write(decrypted)


# ---------- SELECT FILES ----------

def select_files():

    files = filedialog.askopenfilenames()

    for file in files:

        size = get_file_size(file)
        display = f"{file}   ({size})"

        file_list.insert(tk.END, display)


# ---------- REMOVE FILE ----------

def remove_selected():

    selected = file_list.curselection()

    for index in reversed(selected):
        file_list.delete(index)


# ---------- CLEAR FILES ----------

def clear_all():

    file_list.delete(0, tk.END)


# ---------- ENCRYPT BUTTON ----------

def encrypt_selected():

    password = password_entry.get()

    if password == "":
        messagebox.showerror("Error", "Enter password")
        return

    start = time.time()

    total = file_list.size()

    for i in range(total):

        file_path = file_list.get(i).split("   ")[0]

        encrypt_file(file_path, password)

        progress_bar["value"] = ((i + 1) / total) * 100
        root.update_idletasks()

    end = time.time()

    time_label.config(text=f"Encryption Time: {round(end-start,2)} sec")

    messagebox.showinfo("Success", "Encryption Completed")
    progress_bar["value"] = 0


# ---------- DECRYPT BUTTON ----------

def decrypt_selected():

    password = password_entry.get()

    if password == "":
        messagebox.showerror("Error", "Enter password")
        return

    start = time.time()

    total = file_list.size()

    for i in range(total):

        file_path = file_list.get(i).split("   ")[0]

        decrypt_file(file_path, password)

        progress_bar["value"] = ((i + 1) / total) * 100
        root.update_idletasks()

    end = time.time()

    time_label.config(text=f"Decryption Time: {round(end-start,2)} sec")

    messagebox.showinfo("Success", "Decryption Completed")
    progress_bar["value"] = 0


# ---------- DRAG DROP ----------

def drop(event):

    files = root.tk.splitlist(event.data)

    for file in files:

        size = get_file_size(file)
        display = f"{file}   ({size})"

        file_list.insert(tk.END, display)


# ---------- GUI ----------

root = TkinterDnD.Tk()
root.title("Secure File Encryption Tool")
root.geometry("750x600")
root.configure(bg="#1e1e1e")


title = tk.Label(
    root,
    text="Secure File Encryption Tool",
    font=("Arial",20,"bold"),
    bg="#1e1e1e",
    fg="white"
)
title.pack(pady=15)


password_label = tk.Label(root,text="Enter Password",bg="#1e1e1e",fg="white")
password_label.pack()

password_entry = tk.Entry(root,show="*",width=30)
password_entry.pack(pady=5)

password_entry.bind("<KeyRelease>",check_password_strength)


strength_bar = ttk.Progressbar(root,length=200)
strength_bar.pack(pady=5)

strength_label = tk.Label(root,text="Password Strength",bg="#1e1e1e",fg="white")
strength_label.pack()


file_list = tk.Listbox(root,width=90,height=12)
file_list.pack(pady=15)

file_list.drop_target_register(DND_FILES)
file_list.dnd_bind("<<Drop>>",drop)


btn_frame = tk.Frame(root,bg="#1e1e1e")
btn_frame.pack()


tk.Button(btn_frame,text="Select Files",width=15,command=select_files).grid(row=0,column=0,padx=5)

tk.Button(btn_frame,text="Remove Selected",width=15,command=remove_selected).grid(row=0,column=1,padx=5)

tk.Button(btn_frame,text="Clear All",width=15,command=clear_all).grid(row=0,column=2,padx=5)

tk.Button(btn_frame,text="Encrypt",width=15,bg="#27ae60",command=encrypt_selected).grid(row=1,column=0,pady=10)

tk.Button(btn_frame,text="Decrypt",width=15,bg="#2980b9",command=decrypt_selected).grid(row=1,column=1,pady=10)


progress_bar = ttk.Progressbar(root,length=450)
progress_bar.pack(pady=20)


time_label = tk.Label(root,text="Encryption Time: 0 sec",bg="#1e1e1e",fg="white")
time_label.pack()


root.mainloop()