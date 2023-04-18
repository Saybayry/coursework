import tkinter
from tkinter import ttk
from tkinter import *
import sv_ttk



#---------------скитала--------------------------------------------------------



def scitala_crypt(namber: str, text:str , **kwargs)->str:
    try:
        namber = int(namber)
    except Exception as exc:
        return 'неверный ключ'
    if namber >= len(text):
        return text
    arr = ['' for x in range(len(text)//namber+1)]
    for i in range(len(text)):
        arr[i % namber]= arr[i % namber] + text[i]
    return ''.join(arr)


# ------------------ шифр цезаря ----------------------------------------------
alfavitEnRuFull =  'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyzАБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯабвгдеёжзийклмнопрстуфхцчшщъыьэюя'
alfavitEnRu = 'ABCDEFGHIJKLMNOPQRSTUVWXYZАБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ'

alfavitEn = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
alfavitRu = 'АБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ'


def Cesar_crypt( key: str, text:str , en_de: bool,**kwargs)-> str:
    try:
        if en_de:
            key = int(key)
        else:
            key = -int(key)
    except Exception as exc:
        return 'неверный ключ'
    outText = ''
    alf = alfavitEn
    alf2 = alfavitRu
    for i in range(len(text)):
        char = text[i].upper()
        if char in alf:
            outText += alf[(alf.find(char) + key)%len(alf)]
        elif char in alf2:
            outText += alf2[(alf2.find(char) + key) % len(alf2)]
        else:
            outText += text[i]
    return outText


# ------------------ шифр Вижнера ----------------------------------------------

def Vishner_crypt(key: str, text:str, en_de: bool) -> str:
    alf = alfavitEn
    alf2 = alfavitRu
    outText = ''
    for el in key:
        if (el in key) == False :
            return 'неправильный ключ'
    ecr = 1 if en_de else -1
    key *= ((len(text) // len(key)) + 2)
    key, text = key.upper(), text.upper()
    key = list(key)
    for i in range(len(key)):
        charr = key[i]
        if charr in alf:
            key[i] = alf.find(charr)
        if charr in alf2:
            key[i] = alf2.find(charr)
    key = key[0:len(text)]
    for i in range(len(text)):
        char = text[i]
        if char in alf:
            if en_de:
                outText += alf[(alf.find(char) + key[i]) % (len(alf))]
            else:
                outText += alf[(len(alf)+ (alf.find(char) - key[i]) ) % (len(alf))]
        elif char in alf2:
            if en_de:
                outText += alf2[(alf2.find(char) + key[i]) % (len(alf2))]
            else:
                outText += alf2[(len(alf2)+ (alf2.find(char) - key[i]) ) % (len(alf2))]
        else:
            outText += text[i]
    return outText
# ------------------ DES ----------------------------------------------
import base64
from des import DesKey
def DES_crypt(key: str, text:str, en_de: bool) -> str:
    key = bytes(key, 'utf-8') + (b'1' * (8 - (len(bytes(key, 'utf-8')) % 8)))
    key1 = DesKey(key)
    if en_de:
        out = key1.encrypt(bytes(text, 'utf-8'), padding= True)
        out = base64.b64encode(out)
        return out
    else:
        text = base64.b64decode(text)
        out = key1.decrypt(text)
        return out.decode('utf8').replace('\x04', '').replace('\x03', '').replace('\x02', '')
#---------------- AES --------------------------------
import aes
def AES_crypt(key: str, text:str, en_de: bool) -> str:
    key = key.encode('utf-8')
    if len(key) < 16:
        key += key*(16 // len(key))
    key=key[:19]
    key = int(hex(int(key.hex())).zfill(32),16)
    cipher = aes.aes(key, 128)
    segment_length = 32
    if en_de:
        text = text.encode('utf-8').hex()
        print(text)
        text = [text[i:i + segment_length] for i in range(0, len(text), segment_length)]
        text[-1] = (text[-1] + '0000000000000000000000000000')[:32]
        text = [int(el, 16) for el in text]
        text2 = [1 for a in text]
        for i in range(len(text)):
            text2[i] = cipher.enc_once(text[i])
            text2[i] = hex(aes.utils.arr8bit2int(text2[i]))[2:].zfill(32)
        OutText = ''.join(text2)
        OutText = base64.b64encode(bytes(OutText, 'utf-8'))
    else:
        text = base64.b64decode(text)
        text = [text[i:i + segment_length] for i in range(0, len(text), segment_length)]
        text = [int(el, 16) for el in text]
        text2 = [1 for a in text]
        for i in range(len(text)):
            text2[i] = cipher.dec_once(text[i])
            text2[i] = hex(aes.utils.arr8bit2int(text2[i]))[2:].zfill(32)
        OutText = bytes.fromhex(''.join(text2)).decode('utf-8')
        pass
    return OutText















# ------------------Атбаш--------------------------------------------------------
def Atbash_crypt(text:str,**kwargs) -> str:
    text = text.upper()
    alf = alfavitEn
    alf2 = alfavitRu
    outText=''
    for i in range(len(text)):
        char = text[i]
        if char in alf:
            print(len(alf),alf.find(char) , char)
            outText += alf[len(alf) - alf.find(char)-1]
        elif char in alf2:
            print(len(alf2),alf2.find(char) , char)
            outText += alf2[len(alf2) - alf2.find(char) - 1]
        else:
            outText += text[i]
    return outText




def emp():
    print('еще не реализовано')


def main():
    root = tkinter.Tk()
    root.title("шифрование текста")
    root.geometry("680x700")
    root.resizable(width=0, height=0)

    def encrypt(key, text):
        try:
            func = encryption_dict[str(type_encrypt.get())]
            print(func)
            return func(key=key, text=text, en_de=True)
        except Exception as exc:
            print(exc, 'Error__')
            return 'неправильные данные'

    def decrypt(key, text):
        try:
            func = encryption_dict[str(type_encrypt.get())]
            return func(key=key, text=text, en_de=False)
        except Exception as exc:
            print(exc, 'Error__')
            return 'неправильные данные'

    def crypt(*args):
        key = key_text.get()
        text = entry_plaintext.get('0.0',END)
        out: str = ''
        if mode_cript.get() == 'Зашифровать':
            out = encrypt(key,text)
        elif mode_cript.get() == 'Расшифровать':
            out = decrypt(key,text)
        else:
            out = 'вы зашифровать или расшифровать хотите'

        encrypted_text.delete('0.0',END)
        encrypted_text.insert('0.0', out)

##  ----------------------------------------------------------------560/2 250
    up_frame = ttk.Frame(master=root,width=600, height=100)
    up_frame.grid(row=0, column=0, padx=0, pady=0)

    method_selection_label = ttk.LabelFrame(master= up_frame, text='метод ', width=280, height=100)
    method_selection_label.grid(row=0, column=0, padx=20, pady=20)
    method_selection_label.propagate(0)

    method_block_generation = ttk.LabelFrame(master= up_frame, text='ключ 🔑', width=280, height=100)
    method_block_generation.grid(row=0, column=1, padx=10, pady=10)
    method_block_generation.propagate(0)


    key_frame = ttk.LabelFrame( master=method_block_generation, text='введите ключ',height=5,width=640)
    key_frame.pack(fill=BOTH, expand=1 , padx= 10, pady=10,)
    key_frame.propagate(0)

    key_text = Entry(key_frame, width=50,borderwidth=0)
    key_text.pack(anchor=NW, padx=10, pady=6)


    ## тут будут виды шифрования
    encryption_dict: dict[str] = {
        "DES (Data Encryption Standard)/3DES": DES_crypt,# https://pypi.org/project/des/
        "AES; (Advanced Encryption Standard)": AES_crypt,# https://pypi.org/project/aes/
        "Атбаш": Atbash_crypt,
        "Скитала":scitala_crypt,
        "Шифр Цезаря": Cesar_crypt,
        "Шифр виженера": Vishner_crypt,
    }

    encryption_list = list(encryption_dict.keys())
    type_encrypt = tkinter.StringVar(root)
    combobox = ttk.Combobox(master=method_selection_label,
                            state = "readonly",
                            textvariable=type_encrypt,
                            values=encryption_list)
    combobox.pack(anchor=NW, padx=20, pady=20)
    combobox.propagate(0)
    def sel_clear_cmbox(*args): combobox.selection_clear()
    combobox.bind("<<ComboboxSelected>>", sel_clear_cmbox )



##  ----------------------------------------------------------------
    text_frame = ttk.LabelFrame(text='шифрование ', width=660, height=400)
    text_frame.grid(row=1, column=0, padx=20, pady=20,columnspan=2)
    text_frame.propagate(0)

    mode_cript = tkinter.StringVar(root)
    comboboxcr = ttk.Combobox(master=text_frame,
                            state="readonly",
                            textvariable=mode_cript,
                            values=['Зашифровать', 'Расшифровать'])
    comboboxcr.pack(anchor=NW, padx=10, pady=6)
    comboboxcr.propagate(0)


    def sel_clear_cmboxcr(*args):
        comboboxcr.selection_clear()
        button.configure(text=(mode_cript.get()+" 🔐" ))
        print(mode_cript.get())
        out_text1 = 'открытый текст 🔓 ' if mode_cript.get() ==  'Зашифровать'  else 'зашифрованый текст 🔒'
        out_text2 = 'зашифрованый текст 🔒' if mode_cript.get() ==  'Зашифровать'  else 'открытый текст 🔓 '
        entry_plaintext_frame.configure(text=(out_text1))
        encrypted_text_frame.configure(text=(out_text2))

    comboboxcr.bind("<<ComboboxSelected>>", sel_clear_cmboxcr )


    entry_plaintext_frame = ttk.LabelFrame( master=text_frame, text='открытый текст 🔓 ',height=100,width=640)
    entry_plaintext_frame.pack(fill=BOTH, expand=1 , padx= 10, pady=10,)
    entry_plaintext_frame.propagate(0)
    entry_plaintext = Text(master= entry_plaintext_frame, height=10,width=640, borderwidth=0)
    entry_plaintext.pack(fill=BOTH, expand=1 , padx= 9, pady=2 )
    entry_plaintext.propagate(0)

    encrypted_text_frame = ttk.LabelFrame(master=text_frame, text='зашифрованый текст 🔒', height=100, width=640)
    encrypted_text_frame.pack(fill=BOTH, expand=2, padx=10, pady=10, )
    encrypted_text_frame.propagate(0)
    encrypted_text = Text(master=encrypted_text_frame, height=5, borderwidth=0)
    encrypted_text.pack(fill=BOTH, expand=1, padx=9, pady=9,)
    encrypted_text.propagate(0)



    button = ttk.Button(root, text="зашифровать 🔐 ", command=crypt, width =50)
    button.grid(row=4, column=0)

    # This is where the magic happens
    sv_ttk.set_theme("dark")


    root.mainloop()



if __name__ == '__main__':
    main()
