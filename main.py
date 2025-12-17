from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import tkinter as tk
from tkinter import *
from tkinter import ttk,messagebox,Tk,filedialog
from tkinter.scrolledtext import ScrolledText


# Генерация ключа
def generate_key():
    global key
    key = get_random_bytes(32)
    key_entry.delete(0, END)
    key_entry.insert(0, key.hex())
    root.clipboard_append(key_entry.get())
    messagebox.showinfo("Успех", "Ключ скопирован")
# Шифрование
def encrypt():
    try:
        global data
        global nonce # Сохраните nonce для дешифрования
        global ciphertext
        global tag
        data = st.get('1.0',END).encode('utf-8')
        cipher = AES.new(key, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(data)
        nonce = cipher.nonce
        encrypt_entry.delete(0,END)
        encrypt_entry.insert(0,ciphertext)
        print(ciphertext)
    except TypeError:
        pass

# Дешифрование
def decrypt():
    cipher = AES.new(key, AES.MODE_EAX, nonce)
    decrypted = cipher.decrypt_and_verify(ciphertext, tag)
    print("Расшифровано:", decrypted.decode('utf-8'))

# новое шифрование
def New():
    key_entry.delete(0, END)
    encrypt_entry.delete(0,END)


# Сохранение зашифрованного текста в .txt  файл
def Save():
    root = Tk()
    root.withdraw() # Скрываем окно Tkinter

    # Открываем диалоговое окно "Сохранить как"
    file_path = filedialog.asksaveasfilename(
        defaultextension=".txt", # Расширение по умолчанию
        filetypes=[("TXT files", "*.txt"), ("All files", "*.*")], # Фильтры файлов
        title="Сохранить .txt файл как..."
    )

    # Проверяем, был ли выбран путь
    if file_path:
        try:
            # Записываем данные в файл
            with open(file_path, 'w', encoding='utf-8') as file:
                file.write(f'Зашифрованный текст:{encrypt_entry.get()}\nКлюч:{key_entry.get()}')
            messagebox.showinfo('Успех','Успешно сохранено')
        except Exception as e:
            pass
    else:
        messagebox.showerror('Отмена','Cохранение отменено')


key = None # Ключ
data = None # Данные для шифрования (строку преобразуем в байты)
ciphertext = None # Зашифрованный текст
tag = None # тег для проверки





# настройки
root = Tk()
root["bg"] = "#479E92"
root.title("Шифровальщик AES")
root.geometry("1050x550")

st = ScrolledText(root, width=50,  height=10)
st.insert(tk.INSERT,'Пишите тут свой текст для шифрования\nНе забудь сохранить зашифрованный текст и ключ припомощи кнопки Menu>Save')
st.pack(fill=BOTH, side=LEFT, expand=True)



main_menu = Menu()
main_menu["bg"] = "#5A858E"
file_menu = Menu()
file_menu.add_command(label="New",command=New)
file_menu.add_command(label="Save",command=Save)
file_menu.add_separator()
file_menu.add_command(label="Exit")
 
main_menu.add_cascade(label="Menu", menu=file_menu)


label1 = ttk.Label(root,text="КЛЮЧ", width=200,font=("Arial","20","bold"),anchor='center',background="#95E4C1")
label1.pack(padx=6,pady=6,anchor=S)


# поле с ключом
key_entry = ttk.Entry(root, width =100, font=("Arial", 12 )) 
key_entry.pack(pady=20)
# кнопка генерировать ключ
generate_key1 = ttk.Button(root,text = "Генерировать ключ",command=generate_key)
generate_key1.pack(padx=6,pady=6,anchor=S)

label2 = ttk.Label(root,text="Зашифрованный текст", width=200,font=("Arial","20","bold"),anchor='center',background="#95E4C1")
label2.pack(padx=7,pady=7,anchor=S)

# поле с зашифрованным текстом
encrypt_entry = ttk.Entry(root, width=100,font=("font/Verdana.ttf",12))
encrypt_entry.pack(padx=8,pady=8,anchor=S)
# кнопка шифрование текста
encrypt_button = ttk.Button(root,text = "Шифровать",command=encrypt)
encrypt_button.pack(padx=9,pady=9,anchor=S)



root.config(menu=main_menu)
root.mainloop()