from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import tkinter as tk
import json
import base64
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
        global data_to_save
        data = st.get('1.0',END).encode('utf-8')
        cipher = AES.new(key, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(data)
        nonce = cipher.nonce
        data_to_save = {
            'key': base64.b64encode(key).decode('utf-8'),
            'ciphertext': base64.b64encode(ciphertext).decode('utf-8'),
            'nonce': base64.b64encode(nonce).decode('utf-8'),
            'tag': base64.b64encode(tag).decode('utf-8')   
        }
        encrypt_entry.delete(0,END)
        encrypt_entry.insert(0,data_to_save['ciphertext'])

        tag_entry.delete(0,END)
        tag_entry.insert(0,data_to_save['tag'])

        nonce_entry.delete(0,END)
        nonce_entry.insert(0,data_to_save['nonce'])

    except TypeError:
        pass
# Расшифрование
def decrypt():
    global key1
    global ciphertext1
    global nonce1
    global tag1
    file_path = filedialog.askopenfilename(
        defaultextension=".json", # Расширение по умолчанию
        filetypes=[("JSON files", "*.json"), ("All files", "*.*")], # Фильтры файлов
        title="Выберите файл"
    )
    if file_path:
        try:
            with open(file_path, 'r') as f:
                loaded = json.load(f)
                key1 = base64.b64decode(loaded['key'])
                ciphertext1 = base64.b64decode(loaded['ciphertext'])
                nonce1 = base64.b64decode(loaded['nonce'])
                tag1 = base64.b64decode(loaded['tag'])
                cipher = AES.new(key1, AES.MODE_EAX, nonce1)
            decrypted = cipher.decrypt_and_verify(ciphertext1, tag1)
            st1.delete("1.0", END)  # Если st1 — текстовый виджет
            st1.insert("1.0", decrypted.decode('utf-8'))
        except Exception as e:
            messagebox.showerror('Ошибка',e)
    else:
        messagebox.showerror('Отмена','Открытие отменено')  
# новое шифрование
def New():
    key_entry.delete(0, END)
    encrypt_entry.delete(0,END)
    tag_entry.delete(0,END)
    nonce_entry.delete(0,END)
    key = None # Ключ
    ciphertext = None # Зашифрованный текст
    tag = None # тег для проверки
    nonce = None
    data_to_save = None
    st.delete('1.0',tk.END)
# Сохранение зашифрованного текста в .json  файл
def Save():
    global data_to_save
    root = Tk()
    root.withdraw() # Скрываем окно Tkinter

    # Открываем диалоговое окно "Сохранить как"
    file_path = filedialog.asksaveasfilename(
        defaultextension=".json", # Расширение по умолчанию
        filetypes=[("JSON files", "*.json"), ("All files", "*.*")], # Фильтры файлов
        title="Сохранить .json файл как..."
    )

    # Проверяем, был ли выбран путь
    if file_path:
        try:
            # Записываем данные в файл
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(data_to_save, f, indent=4)
            messagebox.showinfo('Успех','Успешно сохранено')
        except Exception as e:
            messagebox.showerror('Ошибка','Некорректный файл')
    else:
        messagebox.showerror('Отмена','Cохранение отменено')

key = None # Ключ
ciphertext = None # Зашифрованный текст
tag = None # тег для проверки
nonce = None
data = None # Данные для шифрования (строку преобразуем в байты)
data_to_save = None
key1 = None
ciphertext1 = None
nonce1 = None
tag1 = None

# настройки
root = Tk()
root.title("Шифровальщик AES")
root.geometry("1050x550")


# создаю набор вкладок
notebook = ttk.Notebook(root)
notebook.pack(expand=True,fill=BOTH)

# Для изменения цвета фона в фреймах
style = ttk.Style()
style.configure("Custom.TFrame",background = "#479E92")


# создаю пару фреймвов
frame1 = ttk.Frame(notebook)
frame2 = ttk.Frame(notebook)
 
frame1.pack(fill=BOTH, expand=True)
frame2.pack(fill=BOTH, expand=True)

# настройка фреймов
frame1.configure(style="Custom.TFrame")
frame2.configure(style="Custom.TFrame")


# добавляю фреймы в качестве вкладок
notebook.add(frame1, text="Шифрование")
notebook.add(frame2, text="Расшифрование")


# создаю поле текста со скроллом
st = ScrolledText(frame1, width=50,  height=10)
st.insert(tk.INSERT,'Пишите тут свой текст для шифрования\nНе забудь сохранить зашифрованный текст,ключ,тэг, вектор инициализации при помощи кнопки Menu>Save')
st.pack(fill=BOTH, side=LEFT, expand=True)



main_menu = Menu(frame1)
main_menu["bg"] = "#5A858E"
file_menu = Menu()
file_menu.add_command(label="New",command=New)
file_menu.add_command(label="Save",command=Save)
file_menu.add_separator()
file_menu.add_command(label="Exit")
main_menu.add_cascade(label="Menu", menu=file_menu)
root.config(menu=main_menu)

# Группа виджетов привязаны к 1 фрейму
# Текст - КЛЮЧ
label1 = ttk.Label(frame1,text="КЛЮЧ", width=200,font=("Arial","20","bold"),anchor='center',background="#95E4C1")
label1.pack()


# поле с ключом
key_entry = ttk.Entry(frame1, width =100, font=("Arial", 12 )) 
key_entry.pack(pady=20)
# кнопка генерировать ключ
generate_key1 = ttk.Button(frame1,text = "Генерировать ключ",command=generate_key)
generate_key1.pack(padx=6,pady=6,anchor=S)

# Текст - Зашифрованный текст
label2 = ttk.Label(frame1,text="Зашифрованный текст", width=200,font=("Arial","20","bold"),anchor='center',background="#95E4C1")
label2.pack(padx=7,pady=7,anchor=S)

# поле с зашифрованным текстом
encrypt_entry = ttk.Entry(frame1, width=100,font=("Arial",12))
encrypt_entry.pack(padx=8,pady=8,anchor=S)
# кнопка шифрование текста
encrypt_button = ttk.Button(frame1,text = "Шифровать",command=encrypt)
encrypt_button.pack(padx=9,pady=9,anchor=S)

# Текст - Тег
label3 = ttk.Label(frame1,text="Тег", width=200,font=("Arial",20,"bold"),anchor='center',background="#95E4C1")
label3.pack(padx=10,pady=10,anchor=S)

tag_entry = ttk.Entry(frame1,width=100,font=("Arial",12))
tag_entry.pack(padx=11,pady=11,anchor=S)

# Текст - Вектор инициализации
label4 = ttk.Label(frame1,text="Вектор инициализации", width=200,font=("Arial",20,"bold"),anchor='center',background="#95E4C1")
label4.pack(padx=12,pady=12,anchor=S)

# поле с вектором инициализации
nonce_entry = ttk.Entry(frame1,width=100,font=("Arial",12))
nonce_entry.pack(padx=13,pady=13,anchor=S)

# Группа виджетов привязаны к 2 фрейму
# создаю поле текста со скроллом
st1 = ScrolledText(frame2, width=50,  height=10)
st1.insert(tk.INSERT,'Тут будет расшифрованный текст')
st1.pack(fill=BOTH, side=LEFT, expand=True)

img = PhotoImage(file='img/eldritch.png')
c = Canvas(frame2,width=400, height=400,bg="#479E92",highlightthickness=0, borderwidth=0)
c.create_image(1, 1, anchor=NW, image=img)
c.pack()

decrypted_btn = ttk.Button(frame2,text='Расшифровать',width=50,command=decrypt)
decrypted_btn.pack()


root.mainloop()