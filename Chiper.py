import tkinter as tk
from tkinter import messagebox, scrolledtext, filedialog
import numpy as np

# Vigenere Cipher
def vigenere_encrypt(plaintext, key):
    key = key.lower()
    key_length = len(key)
    key_as_int = [ord(i) - 97 for i in key]
    plaintext_int = [ord(i) - 97 for i in plaintext.lower() if i.isalpha()]
    ciphertext = ''
    for i in range(len(plaintext_int)):
        value = (plaintext_int[i] + key_as_int[i % key_length]) % 26
        ciphertext += chr(value + 97)
    return ciphertext

def vigenere_decrypt(ciphertext, key):
    key = key.lower()
    key_length = len(key)
    key_as_int = [ord(i) - 97 for i in key]
    ciphertext_int = [ord(i) - 97 for i in ciphertext.lower()]
    plaintext = ''
    for i in range(len(ciphertext_int)):
        value = (ciphertext_int[i] - key_as_int[i % key_length]) % 26
        plaintext += chr(value + 97)
    return plaintext

# Playfair Cipher
def generate_playfair_table(key):
    key = "".join(dict.fromkeys(key.lower().replace("j", "i")))
    alphabet = "abcdefghiklmnopqrstuvwxyz"
    table = []
    for char in key + alphabet:
        if char not in table:
            table.append(char)
    matrix = [table[i:i+5] for i in range(0, 25, 5)]
    return matrix

def playfair_encrypt(plaintext, key):
    matrix = generate_playfair_table(key)
    plaintext = plaintext.replace("j", "i").lower()
    if len(plaintext) % 2 != 0:
        plaintext += 'x'

    def get_position(char):
        for row in range(5):
            for col in range(5):
                if matrix[row][col] == char:
                    return row, col

    ciphertext = ""
    for i in range(0, len(plaintext), 2):
        row1, col1 = get_position(plaintext[i])
        row2, col2 = get_position(plaintext[i + 1])
        if row1 == row2:
            ciphertext += matrix[row1][(col1 + 1) % 5] + matrix[row2][(col2 + 1) % 5]
        elif col1 == col2:
            ciphertext += matrix[(row1 + 1) % 5][col1] + matrix[(row2 + 1) % 5][col2]
        else:
            ciphertext += matrix[row1][col2] + matrix[row2][col1]
    return ciphertext

def playfair_decrypt(ciphertext, key):
    matrix = generate_playfair_table(key)

    def get_position(char):
        for row in range(5):
            for col in range(5):
                if matrix[row][col] == char:
                    return row, col

    plaintext = ""
    for i in range(0, len(ciphertext), 2):
        row1, col1 = get_position(ciphertext[i])
        row2, col2 = get_position(ciphertext[i + 1])
        if row1 == row2:
            plaintext += matrix[row1][(col1 - 1) % 5] + matrix[row2][(col2 - 1) % 5]
        elif col1 == col2:
            plaintext += matrix[(row1 - 1) % 5][col1] + matrix[(row2 - 1) % 5][col2]
        else:
            plaintext += matrix[row1][col2] + matrix[row2][col1]
    return plaintext

# Hill Cipher
def hill_encrypt(plaintext, key_matrix):
    n = len(key_matrix)
    plaintext = [ord(char) - ord('a') for char in plaintext.lower() if char.isalpha()]
    while len(plaintext) % n != 0:
        plaintext.append(ord('x') - ord('a'))
    ciphertext = []
    for i in range(0, len(plaintext), n):
        block = np.dot(key_matrix, plaintext[i:i+n]) % 26
        ciphertext.extend(block)
    return ''.join([chr(c + ord('a')) for c in ciphertext])

def hill_decrypt(ciphertext, key_matrix):
    n = len(key_matrix)
    ciphertext = [ord(char) - ord('a') for char in ciphertext.lower()]
    key_inverse = np.linalg.inv(key_matrix).astype(int) % 26
    plaintext = []
    for i in range(0, len(ciphertext), n):
        block = np.dot(key_inverse, ciphertext[i:i+n]) % 26
        plaintext.extend(block)
    return ''.join([chr(p + ord('a')) for p in plaintext])

# Load and Save File
def load_file():
    file_path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
    if file_path:
        with open(file_path, 'r') as file:
            message_entry.delete(0, tk.END)
            message_entry.insert(0, file.read())

def save_file(text):
    file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
    if file_path:
        with open(file_path, 'w') as file:
            file.write(text)

# Encryption Function
def encrypt():
    cipher = cipher_var.get()
    key = key_entry.get()
    text = message_entry.get()
    if len(key) < 12:
        messagebox.showerror("Error", "Kunci minimal harus 12 karakter.")
        return
    if cipher == "Vigenere":
        result = vigenere_encrypt(text, key)
    elif cipher == "Playfair":
        result = playfair_encrypt(text, key)
    elif cipher == "Hill":
        key_matrix = [[6, 24, 1], [13, 16, 10], [20, 17, 15]]
        result = hill_encrypt(text, key_matrix)
    encrypted_text.delete(1.0, tk.END)
    encrypted_text.insert(tk.END, result)

# Decryption Function
def decrypt():
    cipher = cipher_var.get()
    key = key_entry.get()
    text = message_entry.get()
    if len(key) < 12:
        messagebox.showerror("Error", "Kunci minimal harus 12 karakter.")
        return
    if cipher == "Vigenere":
        result = vigenere_decrypt(text, key)
    elif cipher == "Playfair":
        result = playfair_decrypt(text, key)
    elif cipher == "Hill":
        key_matrix = [[6, 24, 1], [13, 16, 10], [20, 17, 15]]
        result = hill_decrypt(text, key_matrix)
    decrypted_text.delete(1.0, tk.END)
    decrypted_text.insert(tk.END, result)

# Main Interface Setup
root = tk.Tk()
root.title("My Program Cipher")
root.geometry("700x700")
root.configure(bg='#EDE8DC')  # Warna background utama

cipher_var = tk.StringVar(value="Vigenere")

# Key Entry
key_label = tk.Label(root, text="Kunci (min 12 karakter):", bg='#EDE8DC', font=("Arial", 12, "bold"), fg='#A5B68D')
key_label.pack(pady=10)

key_entry = tk.Entry(root, width=50)
key_entry.pack(pady=5)

# Message Entry
message_label = tk.Label(root, text="Pesan:", bg='#EDE8DC', font=("Arial", 12, "bold"), fg='#A5B68D')
message_label.pack(pady=10)

message_entry = tk.Entry(root, width=50)
message_entry.pack(pady=5)

# Cipher Selection
cipher_label = tk.Label(root, text="Pilih Cipher:", bg='#EDE8DC', font=("Arial", 12, "bold"), fg='#A5B68D')
cipher_label.pack(pady=10)

cipher_frame = tk.Frame(root, bg='#EDE8DC')
cipher_frame.pack(pady=5)
for cipher in ["Vigenere", "Playfair", "Hill"]:
    cipher_button = tk.Radiobutton(cipher_frame, text=cipher, variable=cipher_var, value=cipher, bg='#EDE8DC', fg='#A5B68D')
    cipher_button.pack(side=tk.LEFT, padx=10)
    
# Load Button
load_button = tk.Button(root, text="Pilih File", command=load_file, bg='#C1CFA1', fg='#FFFFFF', font=("Arial", 10))
load_button.pack(pady=5)

# Encrypt and Decrypt Buttons
button_frame = tk.Frame(root, bg='#EDE8DC')
button_frame.pack(pady=10)

encrypt_button = tk.Button(button_frame, text="Enkripsi", command=encrypt, bg='#C1CFA1', fg='#FFFFFF', font=("Arial", 10))
encrypt_button.pack(side=tk.LEFT, padx=5)

decrypt_button = tk.Button(button_frame, text="Dekripsi", command=decrypt, bg='#C1CFA1', fg='#FFFFFF', font=("Arial", 10))
decrypt_button.pack(side=tk.LEFT, padx=5)

# Result Frame (sebelahan)
result_frame = tk.Frame(root, bg='#EDE8DC')
result_frame.pack(pady=10)

# Frame Kiri untuk Hasil Enkripsi
encrypted_frame = tk.Frame(result_frame, bg='#EDE8DC')
encrypted_frame.pack(side=tk.LEFT, padx=10)

encrypted_label = tk.Label(encrypted_frame, text="Hasil Enkripsi:", bg='#EDE8DC', font=("Arial", 12, "bold"), fg='#A5B68D')
encrypted_label.pack(anchor='w')
encrypted_text = scrolledtext.ScrolledText(encrypted_frame, width=30, height=5, bg='#E7CCCC', font=("Arial", 12), fg='black')
encrypted_text.pack()

# Frame Kanan untuk Hasil Dekripsi
decrypted_frame = tk.Frame(result_frame, bg='#EDE8DC')
decrypted_frame.pack(side=tk.LEFT, padx=10)

decrypted_label = tk.Label(decrypted_frame, text="Hasil Dekripsi:", bg='#EDE8DC', font=("Arial", 12, "bold"), fg='#A5B68D')
decrypted_label.pack(anchor='w')
decrypted_text = scrolledtext.ScrolledText(decrypted_frame, width=30, height=5, bg='#E7CCCC', font=("Arial", 12), fg='black')
decrypted_text.pack()

root.mainloop()