import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from tkinter.scrolledtext import ScrolledText
import json
import AES1
import RSA1

class CryptoApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Шифровальщик")
        self.root.geometry("1650x650")
        
        # Глобальные переменные для текущей сессии
        self.current_aes_key = None
        self.current_rsa_private_key = None
        self.current_rsa_public_key = None
        self.encrypted_aes_data = None
        self.encrypted_rsa_data = None

        self.setup_ui()
    
    def setup_ui(self):
        # Создание вкладок
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(expand=True, fill=tk.BOTH)
        
        # Стиль
        style = ttk.Style()
        style.configure("Custom.TFrame", background="#4EAEA1")
        
        # Фреймы для вкладок
        self.frame_aes_encrypt = ttk.Frame(self.notebook)
        self.frame_aes_decrypt = ttk.Frame(self.notebook)
        self.frame_rsa_encrypt = ttk.Frame(self.notebook)
        self.frame_rsa_decrypt = ttk.Frame(self.notebook)


        self.frame_aes_encrypt.configure(style="Custom.TFrame")
        self.frame_aes_decrypt.configure(style="Custom.TFrame")
        self.frame_rsa_encrypt.configure(style="Custom.TFrame")
        self.frame_rsa_decrypt.configure(style="Custom.TFrame")
        
        # Добавление фреймов в notebook
        self.notebook.add(self.frame_aes_encrypt, text="Шифрование-AES")
        self.notebook.add(self.frame_aes_decrypt, text="Расшифрование-AES")
        self.notebook.add(self.frame_rsa_encrypt, text="Шифрование-RSA")
        self.notebook.add(self.frame_rsa_decrypt, text="Расшифрование-RSA")
        
        # Настройка интерфейса AES шифрования
        self.setup_aes_encrypt_ui()
        # Настройка интерфейса AES расшифрования
        self.setup_aes_decrypt_ui()
        # Настройка интерфейса RSA шифрования
        self.setup_rsa_encrypt_ui()
        
        # Меню
        self.setup_menu()
    
    def setup_menu(self):
        main_menu = tk.Menu(self.root)
        self.root.config(menu=main_menu)
        
        file_menu = tk.Menu(main_menu, tearoff=0)
        file_menu.add_command(label="New AES", command=self.new_aes_session)
        file_menu.add_command(label="Save AES", command=self.save_aes_data)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)
        
        main_menu.add_cascade(label="Menu-AES", menu=file_menu)
    
    def setup_aes_encrypt_ui(self):
        # Поле ввода текста
        self.text_input = ScrolledText(self.frame_aes_encrypt, width=50, height=10)
        self.text_input.insert(tk.INSERT, 'Пишите тут свой текст для шифрования')
        self.text_input.pack(fill=tk.BOTH, side=tk.LEFT, expand=True)
        
        # Правый фрейм для элементов управления
        right_frame = ttk.Frame(self.frame_aes_encrypt)
        right_frame.configure(style="Custom.TFrame")
        right_frame.pack(fill=tk.BOTH, side=tk.RIGHT, expand=True)
        
        # Ключ
        ttk.Label(right_frame, text="КЛЮЧ", font=("Arial", 20, "bold"), 
                 background="#95E4C1", anchor='center').pack(pady=5, fill=tk.X)
        
        self.key_entry = ScrolledText(right_frame, width=60,height=7)
        self.key_entry.pack(pady=10)
        
        ttk.Button(right_frame, text="Генерировать ключ", 
                  command=self.generate_aes_key).pack(pady=5)
        
        # Зашифрованный текст
        ttk.Label(right_frame, text="Зашифрованный текст", font=("Arial", 20, "bold"),
                 background="#95E4C1", anchor='center').pack(pady=5, fill=tk.X)
        
        self.encrypt_entry = ScrolledText(right_frame, width=60,height=7)
        self.encrypt_entry.pack(pady=10)
        
        ttk.Button(right_frame, text="Шифровать", 
                  command=self.encrypt_aes).pack(pady=5)
        
        # Тег
        ttk.Label(right_frame, text="Тег", font=("Arial", 20, "bold"),
                 background="#95E4C1", anchor='center').pack(pady=5, fill=tk.X)
        
        self.tag_entry = ScrolledText(right_frame, width=60,height=7)
        self.tag_entry.pack(pady=10)
        
        # Вектор инициализации
        ttk.Label(right_frame, text="Вектор инициализации", font=("Arial", 20, "bold"),
                 background="#95E4C1", anchor='center').pack(pady=5, fill=tk.X)
        
        self.nonce_entry = ScrolledText(right_frame, width=60,height=7)
        self.nonce_entry.pack(pady=10)
    
    def setup_aes_decrypt_ui(self):
        # Поле для расшифрованного текста
        self.decrypted_text = ScrolledText(self.frame_aes_decrypt, width=50, height=10)
        self.decrypted_text.insert(tk.INSERT, 'Тут будет расшифрованный текст')
        self.decrypted_text.pack(fill=tk.BOTH, expand=True)
        
        # Кнопка расшифровки
        ttk.Button(self.frame_aes_decrypt, text='Расшифровать из файла',
                  command=self.decrypt_aes_file, width=50).pack(pady=10)
    
    def setup_rsa_encrypt_ui(self):
        right_frame = ttk.Frame(self.frame_rsa_encrypt)
        right_frame.configure(style="Custom.TFrame")
        right_frame.pack(fill=tk.BOTH, side=tk.RIGHT, expand=True)

        ttk.Label(right_frame, text="Ключ-приватный-RSA", font=("Arial", 20, "bold"),
                 background="#95E4C1", anchor='center').pack(pady=10)
        
        self.key_entry_rsa = ScrolledText(right_frame, width=60, height=10)
        self.key_entry_rsa.pack(pady=10)
        
        
        ttk.Label(right_frame, text="Ключ-публичный-RSA", font=("Arial", 20, "bold"),
                 background="#95E4C1", anchor='center').pack(pady=10)
        
        self.key_entry_rsa2 = ScrolledText(right_frame, width=60, height=10)
        self.key_entry_rsa2.pack(pady=10)

        ttk.Button(right_frame, text="Генерировать ключи RSA",
                  command=self.generate_rsa_keys).pack(pady=10)
        
        ttk.Label(right_frame, text="Зашифрованный текст", font=("Arial", 20, "bold"),
                 background="#95E4C1", anchor='center').pack()

        self.encrypt_entry1 = ScrolledText(right_frame, width=60,height=10)
        self.encrypt_entry1.pack(pady=10)

        ttk.Button(right_frame, text="Шифровать",
                  command=self.encrypt_rsa).pack(pady=5)

        self.text_input2 = ScrolledText(self.frame_rsa_encrypt, width=5,height=10)
        self.text_input2.insert(tk.INSERT, 'Пишите тут свой текст для шифрования(желательный маленький)')
        self.text_input2.pack(fill=tk.BOTH,side=tk.LEFT,expand=True)
    
    # Методы AES
    def generate_aes_key(self):
        self.current_aes_key = AES1.generate_aes_key()
        self.key_entry.delete('1.0', tk.END)
        self.key_entry.insert('1.0', self.current_aes_key.hex())
        self.root.clipboard_clear()
        self.root.clipboard_append(self.key_entry.get('1.0'))
        messagebox.showinfo("Успех", "Ключ скопирован в буфер обмена")

    
    def encrypt_aes(self):
        if not self.current_aes_key:
            messagebox.showwarning("Предупреждение", "Сначала сгенерируйте ключ")
            return
        
        plaintext = self.text_input.get("1.0", tk.END).strip()
        if not plaintext:
            messagebox.showwarning("Предупреждение", "Введите текст для шифрования")
            return
        
        self.encrypted_aes_data = AES1.encrypt_aes(self.current_aes_key, plaintext)
        
        self.encrypt_entry.delete('1.0', tk.END)
        self.encrypt_entry.insert('1.0', self.encrypted_aes_data['ciphertext'])
        
        self.tag_entry.delete('1.0', tk.END)
        self.tag_entry.insert('1.0', self.encrypted_aes_data['tag'])
        
        self.nonce_entry.delete('1.0', tk.END)
        self.nonce_entry.insert('1.0', self.encrypted_aes_data['nonce'])
    
    def decrypt_aes_file(self):
        file_path = filedialog.askopenfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
            title="Выберите файл для расшифровки"
        )
        
        if file_path:
            try:
                decrypted_text = AES1.decrypt_aes_from_file(file_path)
                self.decrypted_text.delete("1.0", tk.END)
                self.decrypted_text.insert("1.0", decrypted_text)
            except Exception as e:
                messagebox.showerror("Ошибка", f"Не удалось расшифровать файл: {str(e)}")
    
    def save_aes_data(self):
        if not self.encrypted_aes_data:
            messagebox.showwarning("Предупреждение", "Сначала зашифруйте данные")
            return
        
        file_path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
            title="Сохранить зашифрованные данные"
        )
        
        if file_path:
            try:
                with open(file_path, 'w', encoding='utf-8') as f:
                    json.dump(self.encrypted_aes_data, f, indent=4)
                messagebox.showinfo('Успех', 'Данные успешно сохранены')
            except Exception as e:
                messagebox.showerror('Ошибка', f'Ошибка сохранения: {str(e)}')
    
    def new_aes_session(self):
        self.current_aes_key = None
        self.encrypted_aes_data = None
        self.text_input.delete("1.0", tk.END)
        self.key_entry.delete(0, tk.END)
        self.encrypt_entry.delete(0, tk.END)
        self.tag_entry.delete(0, tk.END)
        self.nonce_entry.delete(0, tk.END)
    
    # Методы RSA
    def generate_rsa_keys(self):
        self.current_rsa_private_key, self.current_rsa_public_key = RSA1.generate_rsa_keys()
        self.public_key_pem = RSA1.get_public_key_pem(self.current_rsa_public_key)
        self.private_key_pem = RSA1.get_public_key_pem(self.current_rsa_private_key)

        # Публичный
        self.key_entry_rsa.delete("1.0", tk.END)
        self.key_entry_rsa.insert("1.0", self.public_key_pem)
        # Приватный
        self.key_entry_rsa2.delete("1.0", tk.END)
        self.key_entry_rsa2.insert("1.0", self.private_key_pem)

    def encrypt_rsa(self):
        if self.current_rsa_private_key == None and self.current_rsa_public_key == None:
            messagebox.showwarning("Предупреждение", "Сначала сгенерируйте ключи")
            return
        plaintext2 = self.text_input.get("1.0", tk.END).strip()
        if plaintext2 == None:
            messagebox.showwarning("Предупреждение", "Введите текст для шифрования")
            return
        self.encrypted_rsa_data = RSA1.encrypt_rsa(self.current_rsa_private_key,self.current_rsa_public_key, plaintext2)
        self.encrypt_entry1.delete('1.0', tk.END)
        self.encrypt_entry1.insert('1.0', self.encrypted_rsa_data['ciphertext_rsa'])

if __name__ == "__main__":
    root = tk.Tk()
    app = CryptoApp(root)
    root.mainloop()