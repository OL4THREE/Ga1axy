import argparse, base64, html, time, hashlib, json, binascii
import urllib, jwt
from PIL import Image
from urllib import parse
from Crypto.Cipher import AES,DES

print('''\033[32m

 ________  ________    _____  ________     ___    ___ ___    ___ 
|\   ____\|\   __  \  / __  \|\   __  \   |\  \  /  /|\  \  /  /|
\ \  \___|\ \  \|\  \|\/_|\  \ \  \|\  \  \ \  \/  / | \  \/  / /
 \ \  \  __\ \   __  \|/ \ \  \ \   __  \  \ \    / / \ \    / / 
  \ \  \|\  \ \  \ \  \   \ \  \ \  \ \  \  /     \/   \/  /  /  
   \ \_______\ \__\ \__\   \ \__\ \__\ \__\/  /\   \ __/  / /    
    \|_______|\|__|\|__|    \|__|\|__|\|__/__/ /\ __\\\___/ /     
                                          |__|/ \|__\|___|/                                             
                                                                \033[36mAuthor:ol4three\033[0m
                                                                \033[36mVersion: 1.0\033[0m
\033[0m''')

# Read txt
def collect_File(filepath):
    try:
        file = open(filepath, 'r')
    except:
        return "\033[31m文件路径错误\033[0m"
    # info = file.read()
    # lines = info.split('\n')
    lines = file.readlines()
    return lines

#Write txt
def Write_File(text,filepath):
    with open(filepath, 'w') as f:
        for i in text:
            f.write(i)
            f.write('\n')
    return "写入完成"

#  URL
def Decode_Url(text):
    resu = urllib.parse.unquote(text.strip())
    return resu

def Encode_Url(text):
    resu = ""
    for char in text:
        encode_char = hex(ord(char)).replace("0x", "%")
        resu += encode_char
    return resu

# Unicodes
def Decode_Unicode(text):
    resu = text.encode().decode('unicode_escape')
    return  resu

def Encode_Unicode(text):
    resu = text.encode('unicode_escape')
    return resu.decode()

# hex
def GetList(string):
    resu = ""
    now = ""
    time = 1
    for i in string:
        now += i
        if time%2==0:
            now = '%'+now
            resu += now
            now = ""
        time +=1
    return resu

def Encode_Url1(text):
    resu = ""
    for char in text:
        encode_char = hex(ord(char)).replace("0x", "%")
        resu += encode_char
    return resu

def Decode_Hex(text):
    resu = text.replace('0x', "")
    resu = resu.replace("\\x","")
    resu = resu.upper()
    resu = Decode_Base16(resu)
    return resu

def Encode_Hex(text):
    resu = Encode_Url1((text.encode('utf-8').decode('unicode_escape')))
    return resu

# Base
def Decode_Base16(text):
    try:

        resu = base64.b16decode(bytes(text.encode().upper()))
        return resu.decode()
    except:
        return "\033[31m解密失败\033[0m"

def Encode_Base16(text):
    resu = base64.b16encode(bytes(text.encode()))
    return resu.decode()

def Decode_Base32(text):
    try:
        resu = base64.b32decode(bytes(text.encode()))
        return resu.decode()
    except:
        return "\033[31m解密失败\033[0m"

def Encode_Base32(text):
    resu = base64.b32encode(bytes(text.encode()))
    return resu.decode()

def Decode_Base64(text):
    try:
        # base pad
        if(len(text)%3!=0):
            text = text + (len(text)%3) * '='
        resu = base64.b64decode(text)
        return resu.decode()
    except:
        return "\033[31m解密失败\033[0m"

def Encode_Base64(text):
    resu = base64.b64encode(bytes(text.encode()))
    return resu.decode()

def Decode_Base85(text):
    try:
        resu = base64.b85decode(bytes(text.encode()))
        return resu.decode()
    except:
        return "\033[31m解密失败\033[0m"

def Encode_Base85(text):
    resu = base64.b85encode(bytes(text.encode()))
    return resu.decode()

#html
def Decode_Html(text):
    resu = html.unescape(text)
    return resu

def Encode_Html(text):
    resu = html.escape(text)
    return resu

#time
def Encode_Time(text):
    try:
        resu = int(time.mktime(time.strptime(text, "%Y-%m-%d %H:%M:%S")))
        return str(resu)
    except:
        return "\033[31m加密失败\033[0m"

def Decode_Time(text):
    try:
        resu = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(int(text)))
        return str(resu)
    except:
        return "\033[31m解密失败\033[0m"

#Java_Runtime
def Decode_Runtime(text):
    return "\033[31m解密失败\033[0m"

def Encode_Runtime(text):
    resu = Encode_Base64(text)
    return  resu

#Morse
MORSE_CODE_DICT = {
                 'A': '.-', 'B': '-...', 'C': '-.-.', 'D': '-..', 'E': '.',
                 'F': '..-.', 'G': '--.', 'H': '....', 'I': '..', 'J': '.---', 'K': '-.-',
                 'L': '.-..', 'M': '--', 'N': '-.', 'O': '---', 'P': '.--.', 'Q': '--.-',
                 'R': '.-.', 'S': '...', 'T': '-', 'U': '..-', 'V': '...-', 'W': '.--',
                 'X': '-..-', 'Y': '-.--', 'Z': '--..',
                 '1': '.----', '2': '..---', '3': '...--', '4': '....-', '5': '.....', '6': '-....',
                 '7': '--...', '8': '---..', '9': '----.', '0': '-----',
                 ', ': '--..--', '.': '.-.-.-', '?': '..--..', '/': '-..-.', '-': '-....-',
                 '(': '-.--.', ')': '-.--.-'
                 }

def Encode_Morse(text):
    try:
        resu = ''
        for letter in text.upper():
            if letter != ' ':
                resu += MORSE_CODE_DICT[letter] + ' '
            else:
                resu += ' '
        return resu
    except:
        return "\033[31m解密失败\033[0m"

def Decode_Morse(text):
    try:
        # 在末尾添加额外空间以访问最后一个摩斯密码
        text += ' '
        resu = ''
        citext = ''
        global i
        for letter in text:
            # 检查空间
            if letter != ' ':
                i = 0
                # 在空格的情况下
                citext += letter
            # 在空间的情况下
            else:
                # 如果 i = 1 表示一个新字符
                i += 1
                # 如果 i = 2 表示一个新单词
                if i == 2:
                    # 添加空格来分隔单词
                    resu += ' '
                else:
                    # 使用它们的值访问密钥（加密的反向）
                    resu += list(MORSE_CODE_DICT.keys())[list(MORSE_CODE_DICT.values()).index(citext)]
                    citext = ''
        return resu
    except:
        return "\033[31m解密失败\033[0m"

#MD5
def Decode_MD5(text):
    try:
        file = open('config/md5.txt', 'r')
        js = file.read()
        dic = json.loads(js)
        file.close()
        for i in dic:
            if (dic[i] == text):
                resu = i
        return resu
    except:
        return "\033[31m解密失败\033[0m"

def Encode_MD5(text):
    resu = hashlib.md5(text.encode('utf-8')).hexdigest()
    return resu

#Sha1
def Decode_sha1(text):
    try:
        file = open('config/sha1.txt', 'r')
        js = file.read()
        dic = json.loads(js)
        file.close()
        for i in dic:
            if (dic[i] == text):
                resu = i
        return resu
    except:
        return "\033[31m解密失败\033[0m"

def Encode_sha1(text):
    resu = hashlib.sha1(text.encode('utf-8')).hexdigest()
    return resu

#Sha224
def Decode_sha224(text):
    try:
        file = open('config/sha224.txt', 'r')
        js = file.read()
        dic = json.loads(js)
        file.close()
        for i in dic:
            if (dic[i] == text):
                resu = i
        return resu
    except:
        return "\033[31m解密失败\033[0m"

def Encode_sha224(text):
    resu = hashlib.sha224(text.encode('utf-8')).hexdigest()
    return resu

#Sha348
def Decode_sha384(text):
    try:
        file = open('config/sha384.txt', 'r')
        js = file.read()
        dic = json.loads(js)
        file.close()
        for i in dic:
            if (dic[i] == text):
                resu = i
        return resu
    except:
        return "\033[31m解密失败\033[0m"

def Encode_sha384(text):
    resu = hashlib.sha384(text.encode('utf-8')).hexdigest()
    return resu

#Sha512
def Decode_sha512(text):
    try:
        file = open('config/sha512.txt', 'r')
        js = file.read()
        dic = json.loads(js)
        file.close()
        for i in dic:
            if (dic[i] == text):
                resu = i
        return resu
    except:
        return "\033[31m解密失败\033[0m"

def Encode_sha512(text):
    resu = hashlib.sha512(text.encode('utf-8')).hexdigest()
    return resu

#Sha256
def Decode_sha256(text):
    try:
        file = open('config/sha256.txt', 'r')
        js = file.read()
        dic = json.loads(js)
        file.close()
        for i in dic:
            if (text == dic[i]):

                resu = i
        return resu
    except:
        return "\033[31m解密失败\033[0m"

def Encode_sha256(text):
    resu = hashlib.sha256(text.encode('utf-8')).hexdigest()
    return resu
#- pading
BLOCK_SIZE = 16  # Bytes
pkcspad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * \
                chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)
unpkcspad = lambda s: s[:-ord(s[len(s) - 1:])]
BLOCK_SIZE2 = 8
pkcspad8 = lambda s: s + (BLOCK_SIZE2 - len(s) % BLOCK_SIZE2) * \
                chr(BLOCK_SIZE2 - len(s) % BLOCK_SIZE2)
unpkcspad8 = lambda s: s[:-ord(s[len(s) - 1:])]
#DES
def des_key(key):
    if (len(key) < 8):
        key = key + (8 - len(key)) * '\0'
    elif (len(key) != 8):
        key = key[:8]
    return key

def des_iv(iv):
    if (len(iv) < 8):
        iv = iv + (8 - len(iv)) * '\0'
    elif (len(iv) != 8):
        iv = iv[:8]
    return iv

def Encode_Des(text, key, iv, mode, result):
    try:
        key = des_key(key)
        if (mode == 'CBC' or mode == 'cbc' or mode == 'Cbc'):
            text = pkcspad8(text)
            iv = des_iv(iv)
            des1 = DES.new(key.encode('utf-8'), DES.MODE_CBC, iv.encode('utf-8'))
            resu = des1.encrypt(text.encode('utf-8'))
            if (result == 'hex' or result == 'Hex' or result == 'HEX'):
                resu = binascii.b2a_hex(resu).decode()
            else:
                resu = base64.b64encode(resu).decode()

        elif (mode == 'ECB' or mode == 'ecb' or mode == 'Ecb'):
            text = pkcspad8(text)
            des1 = DES.new(key.encode('utf-8'), DES.MODE_ECB)
            resu = des1.encrypt(text.encode('utf-8'))
            if (result == 'hex' or result == 'Hex' or result == 'HEX'):
                resu = binascii.b2a_hex(resu).decode()
            else:
                resu = base64.b64encode(resu).decode()

        elif (mode == 'cfb' or mode == 'Cfb' or mode == 'CFB'):
            text = pkcspad8(text)
            iv = des_iv(iv)
            des1 = DES.new(key.encode('utf-8'), DES.MODE_CFB, iv.encode('utf-8'))
            resu = des1.encrypt(text.encode('utf-8'))
            if (result == 'hex' or result == 'Hex' or result == 'HEX'):
                resu = binascii.b2a_hex(resu).decode()
            else:
                resu = base64.b64encode(resu).decode()

        elif (mode == 'ofb' or mode == 'Ofb' or mode == 'OFB'):
            text = pkcspad8(text)
            iv = des_iv(iv)
            des1 = DES.new(key.encode('utf-8'), DES.MODE_OFB, iv.encode('utf-8'))
            resu = des1.encrypt(text.encode('utf-8'))
            if (result == 'hex' or result == 'Hex' or result == 'HEX'):
                resu = binascii.b2a_hex(resu).decode()
            else:
                resu = base64.b64encode(resu).decode()

        elif (mode == 'eax' or mode == 'Eax' or mode == 'EAX'):
            text = pkcspad8(text)
            iv = des_iv(iv)
            des1 = DES.new(key.encode('utf-8'), DES.MODE_EAX, iv.encode('utf-8'))
            resu = des1.encrypt(text.encode('utf-8'))
            if (result == 'hex' or result == 'Hex' or result == 'HEX'):
                resu = binascii.b2a_hex(resu).decode()
            else:
                resu = base64.b64encode(resu).decode()

        else:
            print("\033[33mDES 编码        |      Mode：CBC     \033[0m\033[33m%s\033[0m" % (
                Encode_Des(text, key, iv, "cbc", result)))
            print("\033[33mDES 编码        |      Mode：CFB     \033[0m\033[33m%s\033[0m" % (
                Encode_Des(text, key, iv, "cfb", result)))
            print("\033[33mDES 编码        |      Mode：OFB     \033[0m\033[33m%s\033[0m" % (
                Encode_Des(text, key, iv, "ofb", result)))
            print("\033[33mDES 编码        |      Mode：EAX     \033[0m\033[33m%s\033[0m" % (
                Encode_Des(text, key, iv, "eax", result)))
            resu = Encode_Des(text, key, iv, 'ecb', result)
        return resu
    except TypeError as e:
        return "\033[31m加密失败 请按照加密模式输入KEY—IV\033[0m"


def Decode_Des(text, key, iv, mode, result):
    try:
        key = des_key(key)
        if (mode == 'CBC' or mode == 'cbc' or mode == 'Cbc'):
            iv = des_iv(iv)
            des1 = DES.new(key.encode('utf-8'), DES.MODE_CBC, iv.encode('utf-8'))

            if (result == 'hex' or result == 'Hex' or result == 'HEX'):
                resu = des1.decrypt(binascii.a2b_hex(text)).decode()
            else:
                resu = des1.decrypt(base64.b64decode(text)).decode()


        elif (mode == 'ECB' or mode == 'ecb' or mode == 'Ecb'):
            iv = des_iv(iv)
            des1 = DES.new(key.encode('utf-8'), DES.MODE_ECB)
            try:
                if (result == 'hex' or result == 'Hex' or result == 'HEX'):
                    resu = des1.decrypt(binascii.a2b_hex(text)).decode()
                else:
                    resu = des1.decrypt(base64.b64decode(text)).decode()
            except:
                return "\033[31m解密失败\033[0m"

        elif (mode == 'cfb' or mode == 'Cfb' or mode == 'CFB'):
            iv = des_iv(iv)
            des1 = DES.new(key.encode('utf-8'), DES.MODE_CFB, iv.encode('utf-8'))
            try:
                if (result == 'hex' or result == 'Hex' or result == 'HEX'):
                    resu = des1.decrypt(binascii.a2b_hex(text)).decode()
                else:
                    resu = des1.decrypt(base64.b64decode(text)).decode()
            except:
                return "\033[31m解密失败\033[0m"

        elif (mode == 'ofb' or mode == 'Ofb' or mode == 'OFB'):
            iv = des_iv(iv)
            des1 = DES.new(key.encode('utf-8'), DES.MODE_OFB, iv.encode('utf-8'))
            try:
                if (result == 'hex' or result == 'Hex' or result == 'HEX'):
                    resu = des1.decrypt(binascii.a2b_hex(text)).decode()
                else:
                    resu = des1.decrypt(base64.b64decode(text)).decode()
            except:
                return "\033[31m解密失败\033[0m"

        elif (mode == 'eax' or mode == 'Eax' or mode == 'EAX'):
            iv = des_iv(iv)
            des1 = DES.new(key.encode('utf-8'), DES.MODE_EAX, iv.encode('utf-8'))
            try:
                if (result == 'hex' or result == 'Hex' or result == 'HEX'):
                    resu = des1.decrypt(binascii.a2b_hex(text)).decode()
                else:
                    resu = des1.decrypt(base64.b64decode(text)).decode()
            except:
                return "\033[31m解密失败\033[0m"

        else:
            try:
                print("\033[33mDES 解码        |      Mode：CBC     \033[0m\033[33m%s\033[0m" %
                      Decode_Des(text, key, iv, "cbc", result))
            except:
                print("\033[33mDES 解码        |      Mode：CBC     \033[31m解密失败\033[0m")

            try:
                print("\033[33mDES 解码        |      Mode：CFB     \033[0m\033[33m%s\033[0m" %
                      Decode_Des(text, key, iv, "cfb", result))
            except:
                print("\033[33mDES 解码        |      Mode：CFB     \033[31m解密失败\033[0m")

            try:
                print("\033[33mDES 解码        |      Mode：OFB     \033[0m\033[33m%s\033[0m" %
                      Decode_Des(text, key, iv, "ofb", result))
            except:
                print("\033[33mDES 解码        |      Mode：OFB     \033[31m解密失败\033[0m")

            try:
                print("\033[33mDES 解码        |      Mode：EAX     \033[0m\033[33m%s\033[0m" %
                      Decode_Des(text, key, iv, "eax", result))
            except:
                print("\033[33mDES 解码        |      Mode：EAX     \033[31m解密失败\033[0m")
            resu = Decode_Des(text, key, iv, "ecb", result)
        return resu
    except:
        return "\033[31m解密失败\033[0m"
#AES
def aes_key(key):
    if (16 >= len(key)):
        key = key + (16 - len(key)) * '\0'
        key = key[:16]
    if (24 >= len(key) > 16):
        key = key + (24 - len(key)) * '\0'
        key = key[:24]
    if (len(key) > 24):
        key = key + (32 - len(key)) * '\0'
        key = key[:32]
    key = key.encode('utf8')
    return key
def aes_iv(iv):
    if (16 >= len(iv)):
        iv = iv + (16 - len(iv)) * '\0'
        iv = iv[:16]
    if (24 >= len(iv) > 16):
        iv = iv + (24 - len(iv)) * '\0'
        iv = iv[:24]
    if (len(iv) > 24):
        iv = iv + (32 - len(iv)) * '\0'
        iv = iv[:32]
    return iv

def Encode_AES(text, key, iv, mode, result):
    try:
        data = pkcspad(text)
        if (mode == 'Ecb' or mode =='ECB' or mode =='ecb'):
            key = aes_key(key)
            cipher = AES.new(key, AES.MODE_ECB)
            # 加密后得到的是bytes类型的数据，使用Base64进行编码,返回byte字符串
            resu = cipher.encrypt(data.encode())
            if (result == 'hex' or result == 'HEX' or result == 'Hex'):
                resu = binascii.b2a_hex(resu).decode()
            else:
                resu = base64.b64encode(resu).decode()
        elif (mode == 'Cbc' or mode =='CBC' or mode == 'cbc'):
            key = aes_key(key)
            iv = aes_iv(iv)
            cipher = AES.new(key, AES.MODE_CBC, iv.encode('utf8'))
            resu = cipher.encrypt(data.encode('utf8'))
            # 加密后得到的是bytes类型的数据，使用Base64进行编码,返回byte字符串
            if (result == 'hex' or result == 'HEX' or result == 'Hex'):
                resu = binascii.b2a_hex(resu).decode()
            else:
                resu = base64.b64encode(resu).decode()

        elif (mode == 'CFB' or mode =='cfb' or mode == 'Cfb'):
            key = aes_key(key)
            iv = aes_iv(iv)
            cipher = AES.new(key, AES.MODE_CFB, iv.encode('utf8'))
            resu = cipher.encrypt(data.encode('utf8'))
            # 加密后得到的是bytes类型的数据，使用Base64进行编码,返回byte字符串
            if (result == 'hex' or result == 'HEX' or result == 'Hex'):
                resu = binascii.b2a_hex(resu).decode()
            else:
                resu = base64.b64encode(resu).decode()

        elif (mode == 'OFB' or mode =='ofb' or mode == 'Ofb'):
            key = aes_key(key)
            iv = aes_iv(iv)
            cipher = AES.new(key, AES.MODE_OFB, iv.encode('utf8'))
            resu = cipher.encrypt(data.encode('utf8'))
            # 加密后得到的是bytes类型的数据，使用Base64进行编码,返回byte字符串
            if (result == 'hex' or result == 'HEX' or result == 'Hex'):
                resu = binascii.b2a_hex(resu).decode()
            else:
                resu = base64.b64encode(resu).decode()
        elif (mode == 'EAX' or mode =='Eax' or mode == 'eax'):
            key = aes_key(key)
            iv = aes_iv(iv)
            cipher = AES.new(key, AES.MODE_EAX, iv.encode('utf8'))
            resu = cipher.encrypt(data.encode('utf8'))
            # 加密后得到的是bytes类型的数据，使用Base64进行编码,返回byte字符串
            if (result == 'hex' or result == 'HEX' or result == 'Hex'):
                resu = binascii.b2a_hex(resu).decode()
            else:
                resu = base64.b64encode(resu).decode()
        else:
            print("\033[33mAES 编码        |      Mode：CBC     \033[0m\033[33m%s\033[0m" % (
                Encode_AES(text, key, iv, 'cbc', result)))
            print("\033[33mAES 编码        |      Mode：CFB     \033[0m\033[33m%s\033[0m" % (
                Encode_AES(text, key, iv, 'cfb', result)))
            print("\033[33mAES 编码        |      Mode：OFB     \033[0m\033[33m%s\033[0m" % (
                Encode_AES(text, key, iv, 'ofb', result)))
            print("\033[33mAES 编码        |      Mode：EAX     \033[0m\033[33m%s\033[0m" % (
                Encode_AES(text, key, iv, 'eax', result)))
            resu = Encode_AES(text, key, '', 'ecb', result)
        return resu
    except TypeError as e:
        return "\033[31m加密失败 请按照加密模式输入KEY—IV\033[0m"

def Decode_AES(text, key, iv, mode, result):
    try:

        if (mode == 'Ecb' or mode == 'ECB' or mode == 'ecb'):
            key = aes_key(key)
            if (result == 'Hex' or result == 'hex' or result == 'HEX'):
                data = binascii.a2b_hex(text)
            else:
                data = base64.b64decode(text)
            cipher = AES.new(key, AES.MODE_ECB)
            # 去补位
            resu = unpkcspad(cipher.decrypt(data))
            resu = resu.decode('utf8')
        elif (mode == 'Cbc' or mode == 'CBC' or mode == 'cbc'):
            key = aes_key(key)
            iv = aes_iv(iv)
            if (result == 'Hex' or result == 'hex' or result == 'HEX'):
                data = binascii.a2b_hex(text)
            else:
                data = base64.b64decode(text)
            # 将加密数据转换位bytes类型数据
            cipher = AES.new(key, AES.MODE_CBC, iv.encode('utf8'))
            resu = unpkcspad(cipher.decrypt(data))
            resu = resu.decode('utf8')
        elif (mode == 'cfb' or mode == 'CFB' or mode == 'EAX'):
            key = aes_key(key)
            iv = aes_iv(iv)
            if (result == 'Hex' or result == 'hex' or result == 'HEX'):
                data = binascii.a2b_hex(text)
            else:
                data = base64.b64decode(text)
            # 将加密数据转换位bytes类型数据
            cipher = AES.new(key, AES.MODE_CFB, iv.encode('utf8'))
            resu = unpkcspad(cipher.decrypt(data))
            resu = resu.decode('utf8')
        elif (mode == 'ofb' or mode == 'OFB' or mode == 'Ofb'):
            key = aes_key(key)
            iv = aes_iv(iv)
            data = text.encode('utf8')
            if (result == 'Hex' or result == 'hex' or result == 'HEX'):
                data = binascii.a2b_hex(text)
            else:
                data = base64.b64decode(text)
            # 将加密数据转换位bytes类型数据
            cipher = AES.new(key, AES.MODE_OFB, iv.encode('utf8'))
            resu = unpkcspad(cipher.decrypt(data))
            resu = resu.decode('utf8')
        elif (mode == 'eax' or mode == 'EAX' or mode == 'Eax'):
            key = aes_key(key)
            iv = aes_iv(iv)
            data = text.encode('utf8')
            if (result == 'Hex' or result == 'hex' or result == 'HEX'):
                data = binascii.a2b_hex(text)
            else:
                data = base64.b64decode(text)
            # 将加密数据转换位bytes类型数据
            cipher = AES.new(key, AES.MODE_EAX, iv.encode('utf8'))
            resu = unpkcspad(cipher.decrypt(data))
            resu = resu.decode ('utf8')
        else:
            try:
                print("\033[33mAES 解码        |      Mode：CBC     \033[0m\033[33m%s\033[0m" %
                      Decode_AES(text, key, iv, "cbc", result))
            except:
                print("\033[33mAES 解码        |      Mode：CBC     \033[31m解密失败\033[0m")

            try:
                print("\033[33mAES 解码        |      Mode：CFB     \033[0m\033[33m%s\033[0m" %
                      Decode_AES(text, key, iv, "cfb", result))
            except:
                print("\033[33mAES 解码        |      Mode：CFB     \033[31m解密失败\033[0m")

            try:
                print("\033[33mAES 解码        |      Mode：OFB     \033[0m\033[33m%s\033[0m" %
                      Decode_AES(text, key, iv, "ofb", result))
            except:
                print("\033[33mAES 解码        |      Mode：OFB     \033[31m解密失败\033[0m")

            try:
                print("\033[33mAES 解码        |      Mode：EAX     \033[0m\033[33m%s\033[0m" %
                      Decode_AES(text, key, iv, "eax", result))
            except:
                print("\033[33mAES 解码        |      Mode：EAX     \033[31m解密失败\033[0m")

            resu = Decode_AES(text, key, "", "ECB", "")

        return resu
    except:
        return "\033[31m解密失败\033[0m"

#JWT
headers = {
    "alg": "none",
    "type": "jwt"
    }

def Encode_JWT(text, key, mode):
    try:
        data = eval(text)
        if(mode == 'none' or mode == 'None' or mode == 'NONE'):
          resu = jwt.encode(data, "", headers=headers, algorithm='none')
        else:
          resu = jwt.encode(data, key, algorithm='HS256')
        return resu
    except:
        return "\033[31m加密失败\033[0m"
def Decode_JWT(text):
    try:
        text = text.split('.')
        resu = "headers : " + Decode_Base64(text[0]) +" Payload : " + Decode_Base64(text[1])
        return resu
    except:
        return "\033[31m解密失败\033[0m"


#Base64Img
def Decode_Base64Img(text, filepath):
    try:
        if filepath:
            filepath = filepath
        else:
            filepath = 'result/BaseImg.png'
        imgdata = base64.b64decode(text)
        file = open(filepath, 'wb')
        file.write(imgdata)
        file.close()
        img = Image.open(filepath)
        img.show()
        return filepath
    except:
        return "\033[31m解密失败\033[0m"

def Encode_Base64Img(imgfilepath, filepath):
    try:
        if filepath:
            filepath = filepath
        else:
            filepath = 'result/BaseImg.txt'
        f = open(imgfilepath,'rb')
        resu = base64.b64encode(f.read())
        f.close()
        file = open(filepath,'w')
        file.write(resu.decode())
        file.close()
        return resu, filepath
    except:
        return "\033[31m解密失败\033[0m", "\033[31m解密失败\033[0m"

if __name__ == '__main__':
    #   参数配置
    print("\033[32m当前时间        |      %s\033[0m" % time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(int(time.time()))))
    parser = argparse.ArgumentParser()
    parser.add_argument('-A', dest='ALL', help='ALL Crypto')
    parser.add_argument('-url', dest='URL', help='Encode/Decode URL')
    parser.add_argument('-unicode', dest='unicode', help='Encode/Decode Unicode ')
    parser.add_argument('-hex', dest='hex', help='Encode/Decode hex')
    parser.add_argument('-base', dest='base', help='Encode/Decode base')
    parser.add_argument('-base16', dest='base', help='Encode/Decode base')
    parser.add_argument('-base32', dest='base', help='Encode/Decode base')
    parser.add_argument('-base64', dest='base', help='Encode/Decode base')
    parser.add_argument('-base85', dest='base', help='Encode/Decode base')
    parser.add_argument('-html', dest='html', help='Encode/Decode html')
    parser.add_argument('-time', dest='Time', help='Encode/Decode time')
    parser.add_argument('-runtime', dest='Runtime', help='Encode/Decode Runtime')
    parser.add_argument('-morse', dest='Morse', help='Encode/Decode Morse')
    parser.add_argument('-md5', dest='MD5', help='Encode/Decode Runtime')
    parser.add_argument('-des', dest='DES', help='Encode/Decode des')
    parser.add_argument('-aes', dest='AES', help='Encode/Decode des')
    parser.add_argument('-jwt', dest='JWT', help='Encode/Decode jwt')
    parser.add_argument('-baseimg', dest='BASEIMG', help='Encode/Decode BaseImg')
    parser.add_argument('-sha256', dest='SHA256', help='Encode/Decode sha256')
    parser.add_argument('-sha1', dest='SHA1', help='Encode/Decode sha1')
    parser.add_argument('-sha224', dest='SHA224', help='Encode/Decode sha224')
    parser.add_argument('-sha384', dest='SHA384', help='Encode/Decode sha384')
    parser.add_argument('-sha512', dest='SHA512', help='Encode/Decode sha512')
    parser.add_argument('-key', dest='KEY', help='Encode/Decode KEY')
    parser.add_argument('-iv', dest='IV', help='Encode/Decode IV')
    parser.add_argument('-mode', dest='edmode', help='Encode/Decode ecb/cbc mode')
    parser.add_argument('-resu', dest='result', help='Encode/Decode ecb/cbc resu')
    parser.add_argument('-M', dest='Mode', help='Mode Encode | Decode')
    parser.add_argument('-f', dest='File', help='Filelist Encode/Decode')
    parser.add_argument('-c', dest='Choice', help='Choice Mode')
    parser.add_argument('-o', dest='output', help='output_file default_result/result.txt')
    args = parser.parse_args()

    if args.BASEIMG:
        if args.Mode:
            if (args.Mode == 'e'):
                BaseImgresu , BaseImgfilepath = Encode_Base64Img(args.BASEIMG, args.output)
                print("\033[33m 图片解码        |      \033[0m\033[33m%s\033[0m" % BaseImgresu)
                print("\033[31m 保存路径        |      \033[0m\033[31m%s\033[0m" %BaseImgfilepath)
            if (args.Mode == 'd'):
                text = args.BASEIMG
                if(args.BASEIMG[-3:] == 'txt'):
                    BaseImgfile = open(args.BASEIMG,'r')
                    BaseImgtext = BaseImgfile.read()
                    BaseImgfile.close()
                print("\033[33m保存路径        |      \033[0m\033[33m%s\033[0m" %Decode_Base64Img(BaseImgtext, args.output))
        else:
            BaseImgresu, BaseImgfilepath = Encode_Base64Img(args.BASEIMG, args.output)
            print("\033[33m 图片解码        |      \033[0m\033[33m%s\033[0m" % BaseImgresu)
            print("\033[31m 保存路径        |      \033[0m\033[31m%s\033[0m" % BaseImgfilepath)

    if args.Morse:
        if args.Mode:
            if (args.Mode == 'e'):
                print("\033[33msha256 编码     |      \033[0m\033[33m%s\033[0m" %Encode_Morse(args.Morse))
            if (args.Mode == 'd'):
                print("\033[33msha256 解码     |      \033[0m\033[33m%s\033[0m" %Decode_Morse(args.Morse))
        else:
            print("\033[33msha256 编码     |      \033[0m\033[33m%s\033[0m" %Encode_Morse(args.Morse))

    if args.SHA1:
        if args.Mode:
            if (args.Mode == 'e'):
                print("\033[33msha1 编码       |      \033[0m\033[33m%s\033[0m" %Encode_sha1(args.SHA1))
            if (args.Mode == 'd'):
                print("\033[33msha1 解码       |      \033[0m\033[33m%s\033[0m" %Decode_sha1(args.SHA1))
        else:
            print("\033[33msha1 编码       |      \033[0m\033[33m%s\033[0m" %Encode_sha1(args.SHA1))

    if args.SHA224:
        if args.Mode:
            if (args.Mode == 'e'):
                print("\033[33msha224 编码     |      \033[0m\033[33m%s\033[0m" %Encode_sha224(args.SHA224))
            if (args.Mode == 'd'):
                print("\033[33msha224 解码     |      \033[0m\033[33m%s\033[0m" %Decode_sha224(args.SHA224))
        else:
            print("\033[33msha224 编码     |      \033[0m\033[33m%s\033[0m" %Encode_sha224(args.SHA224))

    if args.SHA256:
        if args.Mode:
            if (args.Mode == 'e'):
                print("\033[33msha256 编码     |      \033[0m\033[33m%s\033[0m" %Encode_sha256(args.SHA256))
            if (args.Mode == 'd'):
                print("\033[33msha256 解码     |      \033[0m\033[33m%s\033[0m" %Decode_sha256(args.SHA256))
        else:
            print("\033[33msha256 编码     |      \033[0m\033[33m%s\033[0m" %Encode_sha256(args.SHA256))

    if args.SHA384:
        if args.Mode:
            if (args.Mode == 'e'):
                print("\033[33msha384 编码     |      \033[0m\033[33m%s\033[0m" %Encode_sha384(args.SHA384))
            if (args.Mode == 'd'):
                print("\033[33msha384 解码     |      \033[0m\033[33m%s\033[0m" %Decode_sha384(args.SHA384))
        else:
            print("\033[33msha384 编码     |      \033[0m\033[33m%s\033[0m" %Encode_sha384(args.SHA384))

    if args.SHA512:
        if args.Mode:
            if (args.Mode == 'e'):
                print("\033[33msha512 编码     |      \033[0m\033[33m%s\033[0m" %Encode_sha512(args.SHA512))
            if (args.Mode == 'd'):
                print("\033[33msha512 解码     |      \033[0m\033[33m%s\033[0m" %Decode_sha512(args.SHA512))
        else:
            print("\033[33msha512 编码     |      \033[0m\033[33m%s\033[0m" %Encode_sha512(args.SHA512))

    if args.DES:
        if args.Mode:
            if (args.Mode == 'e'):
                if (args.edmode == None):
                    edmode = 'ECB'
                else:
                    edmode = args.edmode.upper()
                print("\033[33mDES 编码        |      Mode：%s     \033[0m\033[33m%s\033[0m" % (edmode, Encode_Des(args.DES, args.KEY, args.IV, args.edmode, args.result)))
            if (args.Mode == 'd'):
                if (args.edmode == None):
                    edmode = 'ECB'
                else:
                    edmode = args.edmode.upper()
                print("\033[33mDES 解码        |      Mode：%s     \033[0m\033[33m%s\033[0m" % (edmode, Decode_Des(args.DES, args.KEY, args.IV, args.edmode, args.result)))
        else:
            if (args.edmode == None):
                edmode = 'ECB'
            else:
                edmode = args.edmode.upper()
            print("\033[33mDES 编码        |      Mode：%s     \033[0m\033[33m%s\033[0m" % (edmode, Encode_Des(args.DES, args.KEY, args.IV, args.edmode, args.result)))

    if args.AES:
        if args.Mode:
            if (args.Mode == 'e'):
                if (args.edmode == None):
                    edmode = 'ECB'
                else:
                    edmode = args.edmode.upper()
                print("\033[33mAES 编码        |      Mode：%s     \033[0m\033[33m%s\033[0m" % (edmode, Encode_AES(args.AES, args.KEY, args.IV, args.edmode, args.result)))
            if (args.Mode == 'd'):
                if (args.edmode == None):
                    edmode = 'ECB'
                else:
                    edmode = args.edmode.upper()
                print("\033[33mAES 解码        |      Mode：%s     \033[0m\033[33m%s\033[0m" % (edmode, Decode_AES(args.AES, args.KEY, args.IV, args.edmode, args.result)))
        else:
            if (args.edmode == None):
                edmode = 'ECB'
            else:
                edmode = args.edmode.upper()
            print("\033[33mAES 编码        |      Mode：%s     \033[0m\033[33m%s\033[0m" % (edmode, Encode_AES(args.AES, args.KEY, args.IV, args.edmode, args.result)))

    if args.JWT:
        if args.Mode:
            if (args.Mode == 'e'):
                print("\033[33mJWT 编码        |      \033[0m\033[33m%s\033[0m" % Encode_JWT(args.JWT, args.KEY, args.edmode))
            if (args.Mode == 'd'):
                print("\033[33mJWT 解码        |      \033[0m\033[33m%s\033[0m" % Decode_JWT(args.JWT))
        else:
            print("\033[33mJWT 编码        |      \033[0m\033[33m%s\033[0m" % Encode_JWT(args.JWT, args.KEY, args.edmode))

    if args.MD5:
        if args.Mode:
            if (args.Mode == 'e'):
                print("\033[33mMD5 编码        |      \033[0m\033[33m%s\033[0m" %Encode_MD5(args.MD5))
            if (args.Mode == 'd'):
                print("\033[33mMD5 解码        |      \033[0m\033[33m%s\033[0m" %Decode_MD5(args.MD5))
        else:
            print("\033[33mMD5 编码        |      \033[0m\033[33m%s\033[0m" %Encode_MD5(args.MD5))

    if args.ALL:
        if args.Mode:
            if (args.Mode == 'e'):
                print("\033[33mURL 编码        |      \033[0m\033[33m%s\033[0m" %Encode_Url(args.ALL))
                print("\033[33mUnicode 编码    |      \033[0m\033[33m%s\033[0m" % Encode_Unicode(args.ALL))
                print("\033[33mhex 编码        |      \033[0m\033[33m%s\033[0m" % Encode_Hex(args.ALL).replace("%", ""))
                print("\033[33mbase16 编码     |      \033[0m\033[33m%s\033[0m" %Encode_Base16(args.ALL))
                print("\033[33mbase32 编码     |      \033[0m\033[33m%s\033[0m" %Encode_Base32(args.ALL))
                print("\033[33mbase64 编码     |      \033[0m\033[33m%s\033[0m" %Encode_Base64(args.ALL))
                print("\033[33mbase85 编码     |      \033[0m\033[33m%s\033[0m" %Encode_Base85(args.ALL))
                print("\033[33mHTML 编码       |      \033[0m\033[33m%s\033[0m" %Encode_Html(args.ALL))
                print("\033[33mMD5 编码        |      \033[0m\033[33m%s\033[0m" % Encode_MD5(args.ALL))
                print("\033[33msha1 编码       |      \033[0m\033[33m%s\033[0m" % Encode_sha1(args.ALL))
                print("\033[33msha224 编码     |      \033[0m\033[33m%s\033[0m" % Encode_sha224(args.ALL))
                print("\033[33msha256 编码     |      \033[0m\033[33m%s\033[0m" % Encode_sha256(args.ALL))
                print("\033[33msha384 编码     |      \033[0m\033[33m%s\033[0m" % Encode_sha384(args.ALL))
                print("\033[33msha512 编码     |      \033[0m\033[33m%s\033[0m" % Encode_sha512(args.ALL))
                if (args.edmode == None):
                    edmode = 'ECB'
                else:
                    edmode = args.edmode.upper()
                print("\033[33mDES 编码        |      Mode：%s     \033[0m\033[33m%s\033[0m" % (edmode, Encode_Des(args.ALL, args.KEY, args.IV,
                                                                                           args.edmode, args.result)))
                print("\033[33mAES 编码        |      Mode：%s     \033[0m\033[33m%s\033[0m" % (edmode, Encode_AES(args.ALL, args.KEY, args.IV,
                                                                                           args.edmode, args.result)))
                print(
                    "\033[33mRuntime bash    |      \033[0m\033[33mbash -c {echo,%s}|{base64,-d}|{bash,-i}\033[0m" % Encode_Base64(
                        args.ALL))
                print(
                    "\033[33mRuntime power   |      \033[0m\033[33mpowershell.exe -NonI -W Hidden -NoP -Exec Bypass -Enc %s\033[0m" % Encode_Base64(
                        args.ALL))
                print(
                    "\033[33mRuntime py      |      \033[0m\033[33mpython -c exec('%s'.decode('base64'))\033[0m" % Encode_Base64(
                        args.ALL))
                print(
                    "\033[33mRuntime perl    |      \033[0m\033[33mperl -MMIME::Base64 -e eval(decode_base64('%s'))\033[0m" % Encode_Base64(
                        args.ALL))
                print("\033[33mJWT 编码        |      \033[0m\033[33m%s\033[0m" % Encode_JWT(args.ALL, args.KEY,
                                                                                           args.edmode))
                print("\033[33m时间戳 编码     |      \033[0m\033[33m%s\033[0m" % Encode_Time(args.ALL))
            if (args.Mode == 'd'):
                print("\033[33mURL 解码        |      \033[0m\033[33m%s\033[0m" %Decode_Url(args.ALL))
                print("\033[33mUnicode 解码    |      \033[0m\033[33m%s\033[0m" % Decode_Unicode(args.ALL))
                print("\033[33mhex 解码        |      \033[0m\033[33m%s\033[0m" % Decode_Hex(args.ALL))
                print("\033[33mbase16 解码     |      \033[0m\033[33m%s\033[0m" %Decode_Base16(args.ALL))
                print("\033[33mbase32 解码     |      \033[0m\033[33m%s\033[0m" %Decode_Base32(args.ALL))
                print("\033[33mbase64 解码     |      \033[0m\033[33m%s\033[0m" %Decode_Base64(args.ALL))
                print("\033[33mbase85 解码     |      \033[0m\033[33m%s\033[0m" %Decode_Base85(args.ALL))
                print("\033[33mHTML 解码       |      \033[0m\033[33m%s\033[0m" % Decode_Html(args.ALL))
                print("\033[33mMD5 解码        |      \033[0m\033[33m%s\033[0m" % Decode_MD5(args.ALL))
                print("\033[33msha1 解码       |      \033[0m\033[33m%s\033[0m" % Decode_sha1(args.ALL))
                print("\033[33msha224 解码     |      \033[0m\033[33m%s\033[0m" % Decode_sha224(args.ALL))
                print("\033[33msha256 解码     |      \033[0m\033[33m%s\033[0m" % Decode_sha256(args.ALL))
                print("\033[33msha384 解码     |      \033[0m\033[33m%s\033[0m" % Decode_sha384(args.ALL))
                print("\033[33msha512 解码     |      \033[0m\033[33m%s\033[0m" % Decode_sha512(args.ALL))
                if (args.edmode == None):
                    edmode = 'ECB'
                else:
                    edmode = args.edmode.upper()
                print("\033[33mDES 解码        |      Mode：%s     \033[0m\033[33m%s\033[0m" % (edmode, Decode_Des(args.ALL, args.KEY, args.IV,
                                                                                           args.edmode, args.result)))
                print("\033[33mAES 解码        |      Mode：%s     \033[0m\033[33m%s\033[0m" % (edmode, Decode_AES(args.ALL, args.KEY, args.IV,
                                                                                           args.edmode, args.result)))
                print("\033[33mRuntime 解码    |      %s\033[0m" % Decode_Runtime(args.Time))
                print("\033[33mJWT 解码        |      \033[0m\033[33m%s\033[0m" % Decode_JWT(args.ALL))
                print("\033[33m时间戳 解码     |      \033[0m\033[33m%s\033[0m" % Decode_Time(args.ALL))
        else:
            print("\033[33mURL 编码        |      \033[0m\033[33m%s\033[0m" % Encode_Url(args.ALL))
            print("\033[33mUnicode 编码    |      \033[0m\033[33m%s\033[0m" % Encode_Unicode(args.ALL))
            print("\033[33mbase16 编码     |      \033[0m\033[33m%s\033[0m" % Encode_Base16(args.ALL))
            print("\033[33mbase32 编码     |      \033[0m\033[33m%s\033[0m" % Encode_Base32(args.ALL))
            print("\033[33mbase64 编码     |      \033[0m\033[33m%s\033[0m" % Encode_Base64(args.ALL))
            print("\033[33mbase85 编码     |      \033[0m\033[33m%s\033[0m" % Encode_Base85(args.ALL))
            print("\033[33mHTML 编码       |      \033[0m\033[33m%s\033[0m" % Encode_Html(args.ALL))
            print("\033[33mMD5 编码        |      \033[0m\033[33m%s\033[0m" % Encode_MD5(args.ALL))
            print("\033[33msha1 编码       |      \033[0m\033[33m%s\033[0m" % Encode_sha1(args.ALL))
            print("\033[33msha224 编码     |      \033[0m\033[33m%s\033[0m" % Encode_sha224(args.ALL))
            print("\033[33msha256 编码     |      \033[0m\033[33m%s\033[0m" % Encode_sha256(args.ALL))
            print("\033[33msha384 编码     |      \033[0m\033[33m%s\033[0m" % Encode_sha384(args.ALL))
            print("\033[33msha512 编码     |      \033[0m\033[33m%s\033[0m" % Encode_sha512(args.ALL))
            if (args.edmode == None):
                edmode = 'ECB'
            else:
                edmode = args.edmode.upper()
            print("\033[33mDES 编码        |      Mode：%s     \033[0m\033[33m%s\033[0m" % (edmode, Encode_Des(args.ALL, args.KEY, args.IV,
                                                                                           args.edmode, args.result)))
            print("\033[33mAES 编码        |      Mode：%s     \033[0m\033[33m%s\033[0m" % (edmode, Encode_AES(args.ALL, args.KEY, args.IV,
                                                                                       args.edmode, args.result)))
            print(
                "\033[33mRuntime bash    |      \033[0m\033[33mbash -c {echo,%s}|{base64,-d}|{bash,-i}\033[0m" % Encode_Base64(
                    args.ALL))
            print(
                "\033[33mRuntime power   |      \033[0m\033[33mpowershell.exe -NonI -W Hidden -NoP -Exec Bypass -Enc %s\033[0m" % Encode_Base64(
                    args.ALL))
            print(
                "\033[33mRuntime py      |      \033[0m\033[33mpython -c exec('%s'.decode('base64'))\033[0m" % Encode_Base64(
                    args.ALL))
            print(
                "\033[33mRuntime perl    |      \033[0m\033[33mperl -MMIME::Base64 -e eval(decode_base64('%s'))\033[0m" % Encode_Base64(
                    args.ALL))
            print("\033[33mJWT 编码        |      \033[0m\033[33m%s\033[0m" % Encode_JWT(args.ALL, args.KEY,
                                                                                       args.edmode))
            print("\033[33m时间戳 编码     |      \033[0m\033[33m%s\033[0m" % Encode_Time(args.ALL))

    if args.URL:
        if args.Mode:
            if (args.Mode == 'e'):
                print("\033[33mURL 编码        |      \033[0m\033[33m%s\033[0m" %Encode_Url(args.URL))
            if (args.Mode == 'd'):
                print("\033[33mURL 解码        |      \033[0m\033[33m%s\033[0m" %Decode_Url(args.URL))
        else:
            print("\033[33mURL 编码        |      \033[0m\033[33m%s\033[0m" % Encode_Url(args.URL))

    if args.unicode:
        if args.Mode:
            if (args.Mode == 'e'):
                print("\033[33mUnicode 编码    |      \033[0m\033[33m%s\033[0m" %Encode_Unicode(args.unicode))
            if (args.Mode == 'd'):
                print("\033[33mUnicode 解码    |      \033[0m\033[33m%s\033[0m" %Decode_Unicode(args.unicode))
        else:
            print("\033[33mUnicode 编码    |      \033[0m\033[33m%s\033[0m" % Encode_Unicode(args.unicode))

    if args.hex:
        if args.Mode:
            if (args.Mode == 'e'):
                print("\033[33mhex 编码        |      \033[0m\033[33m%s\033[0m" % Encode_Hex(args.hex).replace("%",""))
                print("\033[33mhex 编码        |      \033[0m\033[33m%s\033[0m" % Encode_Hex(args.hex).replace("%","0x"))
                print("\033[33mhex 编码        |      \033[0m\033[33m%s\033[0m" % Encode_Hex(args.hex).replace("%","\\x"))
            if (args.Mode == 'd'):
                print("\033[33mhex 解码        |      \033[0m\033[33m%s\033[0m" % Decode_Hex(args.hex))
        else:
            print("\033[33mhex 编码        |      \033[0m\033[33m%s\033[0m" % Encode_Hex(args.hex).replace("%", ""))
            print("\033[33mhex 编码        |      \033[0m\033[33m%s\033[0m" % Encode_Hex(args.hex).replace("%", "0x"))
            print("\033[33mhex 编码        |      \033[0m\033[33m%s\033[0m" % Encode_Hex(args.hex).replace("%", "\\x"))

    if args.base:
        if args.Mode:
            if (args.Mode == 'e'):
                print("\033[33mbase16 编码     |      \033[0m\033[33m%s\033[0m" %Encode_Base16(args.base))
                print("\033[33mbase32 编码     |      \033[0m\033[33m%s\033[0m" %Encode_Base32(args.base))
                print("\033[33mbase64 编码     |      \033[0m\033[33m%s\033[0m" %Encode_Base64(args.base))
                print("\033[33mbase85 编码     |      \033[0m\033[33m%s\033[0m" %Encode_Base85(args.base))
            if (args.Mode == 'd'):
                print("\033[33mbase16 解码     |      \033[0m\033[33m%s\033[0m" %Decode_Base16(args.base))
                print("\033[33mbase32 解码     |      \033[0m\033[33m%s\033[0m" %Decode_Base32(args.base))
                print("\033[33mbase64 解码     |      \033[0m\033[33m%s\033[0m" %Decode_Base64(args.base))
                print("\033[33mbase85 解码     |      \033[0m\033[33m%s\033[0m" %Decode_Base85(args.base))
        else:
            print("\033[33mbase16 编码     |      \033[0m\033[33m%s\033[0m" % Encode_Base16(args.base))
            print("\033[33mbase32 编码     |      \033[0m\033[33m%s\033[0m" % Encode_Base32(args.base))
            print("\033[33mbase64 编码     |      \033[0m\033[33m%s\033[0m" % Encode_Base64(args.base))
            print("\033[33mbase85 编码     |      \033[0m\033[33m%s\033[0m" % Encode_Base85(args.base))

    if args.html:
        if args.Mode:
            if (args.Mode == 'e'):
                print("\033[33mHTML 编码       |      \033[0m\033[33m%s\033[0m" %Encode_Html(args.html))
            if (args.Mode == 'd'):
                print("\033[33mHTML 解码       |      \033[0m\033[33m%s\033[0m" %Decode_Html(args.html))
        else:
            print("\033[33mHTML 编码       |      \033[0m\033[33m%s\033[0m" % Encode_Html(args.html))

    if args.Time:
        if args.Mode:
            if (args.Mode == 'e'):
                print("\033[36m时间戳 编码     |      %s\033[0m" %Encode_Time(args.Time))
            if (args.Mode == 'd'):
                print("\033[36m时间戳 解码     |      %s\033[0m" %Decode_Time(args.Time))
        else:
            print("\033[36m时间戳 编码     |      %s\033[0m" % Encode_Time(args.Time))

    if args.Runtime:
        if args.Mode:
            if (args.Mode == 'e'):
                print("\033[33mRuntime bash    |      \033[0m\033[33mbash -c {echo,%s}|{base64,-d}|{bash,-i}\033[0m" % Encode_Runtime(args.Runtime))
                print("\033[33mRuntime power   |      \033[0m\033[33mpowershell.exe -NonI -W Hidden -NoP -Exec Bypass -Enc %s\033[0m" % Encode_Runtime(args.Runtime))
                print("\033[33mRuntime py      |      \033[0m\033[33mpython -c exec('%s'.decode('base64'))\033[0m" % Encode_Runtime(args.Runtime))
                print("\033[33mRuntime perl    |      \033[0m\033[33mperl -MMIME::Base64 -e eval(decode_base64('%s'))\033[0m" % Encode_Runtime(args.Runtime))
            if (args.Mode == 'd'):
                print("\033[36mRuntime 解码    |      %s\033[0m" %Decode_Runtime(args.Time))
        else:
            print(
                "\033[33mRuntime bash    |      \033[0m\033[33mbash -c {echo,%s}|{base64,-d}|{bash,-i}\033[0m" % Encode_Runtime(
                    args.Runtime))
            print(
                "\033[33mRuntime power   |      \033[0m\033[33mpowershell.exe -NonI -W Hidden -NoP -Exec Bypass -Enc %s\033[0m" % Encode_Runtime(
                    args.Runtime))
            print(
                "\033[33mRuntime py      |      \033[0m\033[33mpython -c exec('%s'.decode('base64'))\033[0m" % Encode_Runtime(
                    args.Runtime))
            print(
                "\033[33mRuntime perl    |      \033[0m\033[33mperl -MMIME::Base64 -e eval(decode_base64('%s'))\033[0m" % Encode_Runtime(
                    args.Runtime))

    if args.File:
        resu = []
        result = collect_File(args.File)
        if(args.Mode == 'e'):
            if (args.Choice=='url' or args.Choice == 'URL' or args.Choice== 'Url'):
                for i in result:
                    temp = Encode_Url(i.strip())
                    resu.append(temp)
                    print("\033[33m%s\033[0m\033[38m :: \033[0m\033[36m%s\033[0m" % (i.strip('\n') , temp))
            if (args.Choice=='md5' or args.Choice == 'MD5' or args.Choice == 'Md5'):
                for i in result:
                    temp = Encode_MD5(i.strip())
                    resu.append(temp)
                    print("\033[33m%s\033[0m\033[38m :: \033[0m\033[36m%s\033[0m" % (i.strip('\n') , temp))
            if (args.Choice=='sha1' or args.Choice == 'SHA1' or args.Choice == 'Sha1'):
                for i in result:
                    temp = Encode_sha1(i.strip())
                    resu.append(temp)
                    print("\033[33m%s\033[0m\033[38m :: \033[0m\033[36m%s\033[0m" % (i.strip('\n') , temp))
            if (args.Choice=='sha224' or args.Choice == 'SHA224' or args.Choice == 'Sha224'):
                for i in result:
                    temp = Encode_sha224(i.strip())
                    resu.append(temp)
                    print("\033[33m%s\033[0m\033[38m :: \033[0m\033[36m%s\033[0m" % (i.strip('\n') , temp))
            if (args.Choice=='sha256' or args.Choice == 'SHA256' or args.Choice == 'Sha256'):
                for i in result:
                    temp = Encode_sha256(i.strip())
                    resu.append(temp)
                    print("\033[33m%s\033[0m\033[38m :: \033[0m\033[36m%s\033[0m" % (i.strip('\n') , temp))
            if (args.Choice=='sha384' or args.Choice == 'SHA384' or args.Choice == 'Sha384'):
                for i in result:
                    temp = Encode_sha384(i.strip())
                    resu.append(temp)
                    print("\033[33m%s\033[0m\033[38m :: \033[0m\033[36m%s\033[0m" % (i.strip('\n') , temp))
            if (args.Choice=='sha512' or args.Choice == 'SHA512' or args.Choice == 'Sha512'):
                for i in result:
                    temp = Encode_sha512(i.strip())
                    resu.append(temp)
                    print("\033[33m%s\033[0m\033[38m :: \033[0m\033[36m%s\033[0m" % (i.strip('\n') , temp))
            if (args.Choice=='Unicode' or args.Choice=='unicode' or args.Choice=='UNICODE'):
                for i in result:
                    temp = Encode_Unicode(i.strip())
                    resu.append(temp)
                    print("\033[33m%s\033[0m\033[38m :: \033[0m\033[36m%s\033[0m" % (i.strip('\n') , temp))
            if (args.Choice=='hex' or args.Choice=='HEX' or args.Choice=='Hex'):
                for i in result:
                    temp = Encode_Hex(i.strip()).replace("%", "")
                    resu.append(temp)
                    print("\033[33m%s\033[0m\033[38m :: \033[0m\033[36m%s\033[0m" % (i.strip('\n') , temp))
            if (args.Choice=='Shellcode' or args.Choice=='shellcode' or args.Choice=='SHELLCODE'):
                for i in result:
                    temp = Encode_Hex(i.strip()).replace("%", "\\x")
                    resu.append(temp)
                    print("\033[33m%s\033[0m\033[38m :: \033[0m\033[36m%s\033[0m" % (i.strip('\n') , temp))
            if (args.Choice=='Base64' or args.Choice=='base64' or args.Choice=='BASE64'):
                for i in result:
                    temp = Encode_Base64(i.strip())
                    resu.append(temp)
                    print("\033[33m%s\033[0m\033[38m :: \033[0m\033[36m%s\033[0m" % (i.strip('\n') , temp))
            if (args.Choice=='Base16' or args.Choice=='base16' or args.Choice=='BASE16'):
                for i in result:
                    temp = Encode_Base16(i.strip())
                    resu.append(temp)
                    print("\033[33m%s\033[0m\033[38m :: \033[0m\033[36m%s\033[0m" % (i.strip('\n') , temp))
            if (args.Choice=='Base32' or args.Choice=='base32' or args.Choice=='BASE32'):
                for i in result:
                    temp = Encode_Base32(i.strip())
                    resu.append(temp)
                    print("\033[33m%s\033[0m\033[38m :: \033[0m\033[36m%s\033[0m" % (i.strip('\n') , temp))
            if (args.Choice=='Base85' or args.Choice=='base85' or args.Choice=='BASE85'):
                for i in result:
                    temp = Encode_Base85(i.strip())
                    resu.append(temp)
                    print("\033[33m%s\033[0m\033[38m :: \033[0m\033[36m%s\033[0m" % (i.strip('\n') , temp))
            if (args.Choice=='Html' or args.Choice=='html' or args.Choice=='HTML'):
                for i in result:
                    temp = Encode_Html(i.strip())
                    resu.append(temp)
                    print("\033[33m%s\033[0m\033[38m :: \033[0m\033[36m%s\033[0m" % (i.strip('\n') , temp))
            if (args.Choice=='Time' or args.Choice=='time' or args.Choice=='TIME'):
                for i in result:
                    temp = Encode_Time(i.strip())
                    resu.append(temp)
                    print("\033[33m%s\033[0m\033[38m :: \033[0m\033[36m%s\033[0m" % (i.strip('\n') , temp))
            if (args.Choice=='DES' or args.Choice=='des' or args.Choice=='Des'):
                for i in result:
                    temp = Encode_Des(i.strip(), args.KEY, args.IV, args.edmode, args.result)
                    resu.append(temp)
                    print("\033[33m%s\033[0m\033[38m :: \033[0m\033[36m%s\033[0m" % (i.strip('\n') , temp))
            if (args.Choice=='AES' or args.Choice=='aes' or args.Choice=='Aes'):
                for i in result:
                    temp = Encode_AES(i.strip(), args.KEY, args.IV, args.edmode, args.result)
                    resu.append(temp)
                    print("\033[33m%s\033[0m\033[38m :: \033[0m\033[36m%s\033[0m" % (i.strip('\n') , temp))
            if (args.Choice=='jwt' or args.Choice=='Jwt' or args.Choice=='JWT'):
                for i in result:
                    temp = Encode_JWT(i.strip(), args.KEY, args.edmode)
                    resu.append(temp)
                    print("\033[33m%s\033[0m\033[38m :: \033[0m\033[36m%s\033[0m" % (i.strip('\n') , temp))
        elif (args.Mode == 'd'):
            if (args.Choice == 'url' or args.Choice == 'URL' or args.Choice == 'Url'):
                for i in result:
                    temp = 1
                    resu.append(Decode_Url(i.strip()))
                    print("\033[33m%s\033[0m\033[38m :: \033[0m\033[36m%s\033[0m" % (i.strip('\n') , temp))
            if (args.Choice == 'md5' or args.Choice == 'MD5' or args.Choice == 'Md5'):
                for i in result:
                    temp = Decode_MD5(i.strip())
                    resu.append(temp)
                    print("\033[33m%s\033[0m\033[38m :: \033[0m\033[36m%s\033[0m" % (i.strip('\n') , temp))
            if (args.Choice=='sha1' or args.Choice == 'SHA1' or args.Choice == 'Sha1'):
                for i in result:
                    temp = Decode_sha1(i.strip())
                    resu.append(temp)
                    print("\033[33m%s\033[0m\033[38m :: \033[0m\033[36m%s\033[0m" % (i.strip('\n') , temp))
            if (args.Choice=='sha224' or args.Choice == 'SHA224' or args.Choice == 'Sha224'):
                for i in result:
                    temp = Decode_sha224(i.strip())
                    resu.append(temp)
                    print("\033[33m%s\033[0m\033[38m :: \033[0m\033[36m%s\033[0m" % (i.strip('\n') , temp))
            if (args.Choice=='sha256' or args.Choice == 'SHA256' or args.Choice == 'Sha256'):
                for i in result:
                    temp = Decode_sha256(i.strip())
                    resu.append(temp)
                    print("\033[33m%s\033[0m\033[38m :: \033[0m\033[36m%s\033[0m" % (i.strip('\n') , temp))
            if (args.Choice=='sha384' or args.Choice == 'SHA384' or args.Choice == 'Sha384'):
                for i in result:
                    temp = Decode_sha384(i.strip())
                    resu.append(temp)
                    print("\033[33m%s\033[0m\033[38m :: \033[0m\033[36m%s\033[0m" % (i.strip('\n') , temp))
            if (args.Choice=='sha512' or args.Choice == 'SHA512' or args.Choice == 'Sha512'):
                for i in result:
                    temp = Decode_sha512(i.strip())
                    resu.append(temp)
                    print("\033[33m%s\033[0m\033[38m :: \033[0m\033[36m%s\033[0m" % (i.strip('\n') , temp))
            if (args.Choice == 'Unicode' or args.Choice == 'unicode' or args.Choice == 'UNICODE'):
                for i in result:
                    temp = Decode_Unicode(i.strip())
                    resu.append(temp)
                    print("\033[33m%s\033[0m\033[38m :: \033[0m\033[36m%s\033[0m" % (i.strip('\n') , temp))
            if (args.Choice == 'hex' or args.Choice == 'HEX' or args.Choice == 'Hex'):
                for i in result:
                    temp = Decode_Hex(i.strip()).replace("%", "")
                    resu.append(temp)
                    print("\033[33m%s\033[0m\033[38m :: \033[0m\033[36m%s\033[0m" % (i.strip('\n') , temp))
            if (args.Choice == 'Shellcode' or args.Choice == 'shellcode' or args.Choice == 'SHELLCODE'):
                for i in result:
                    temp = Decode_Hex(i.strip()).replace("%", "\\x")
                    resu.append(temp)
                    print("\033[33m%s\033[0m\033[38m :: \033[0m\033[36m%s\033[0m" % (i.strip('\n') , temp))
            if (args.Choice == 'Base64' or args.Choice == 'base64' or args.Choice == 'BASE64'):
                for i in result:
                    temp = Decode_Base64(i.strip())
                    resu.append(temp)
                    print("\033[33m%s\033[0m\033[38m :: \033[0m\033[36m%s\033[0m" % (i.strip('\n') , temp))
            if (args.Choice == 'Base16' or args.Choice == 'base16' or args.Choice == 'BASE16'):
                for i in result:
                    temp = Decode_Base16(i.strip())
                    resu.append(temp)
                    print("\033[33m%s\033[0m\033[38m :: \033[0m\033[36m%s\033[0m" % (i.strip('\n') , temp))
            if (args.Choice == 'Base32' or args.Choice == 'base32' or args.Choice == 'BASE32'):
                for i in result:
                    temp = Decode_Base32(i.strip())
                    resu.append(temp)
                    print("\033[33m%s\033[0m\033[38m :: \033[0m\033[36m%s\033[0m" % (i.strip('\n') , temp))
            if (args.Choice == 'Base85' or args.Choice == 'base85' or args.Choice == 'BASE85'):
                for i in result:
                    temp = Decode_Base85(i.strip())
                    resu.append(temp)
                    print("\033[33m%s\033[0m\033[38m :: \033[0m\033[36m%s\033[0m" % (i.strip('\n') , temp))
            if (args.Choice == 'Html' or args.Choice == 'html' or args.Choice == 'HTML'):
                for i in result:
                    temp = Decode_Html(i.strip())
                    resu.append(temp)
                    print("\033[33m%s\033[0m\033[38m :: \033[0m\033[36m%s\033[0m" % (i.strip('\n') , temp))
            if (args.Choice == 'Time' or args.Choice == 'time' or args.Choice == 'TIME'):
                for i in result:
                    temp = Decode_Time(i.strip())
                    resu.append(temp)
                    print("\033[33m%s\033[0m\033[38m :: \033[0m\033[36m%s\033[0m" % (i.strip('\n') , temp))
            if (args.Choice=='DES' or args.Choice=='des' or args.Choice=='Des'):
                for i in result:
                    temp = Decode_Des(i.strip(), args.KEY, args.IV, args.edmode, args.result)
                    resu.append(temp)
                    print("\033[33m%s\033[0m\033[38m :: \033[0m\033[36m%s\033[0m" % (i.strip('\n') , temp))
            if (args.Choice=='AES' or args.Choice=='aes' or args.Choice=='Aes'):
                for i in result:
                    temp = Decode_AES(i.strip(), args.KEY, args.IV, args.edmode, args.result)
                    resu.append(temp)
                    print("\033[33m%s\033[0m\033[38m :: \033[0m\033[36m%s\033[0m" % (i.strip('\n') , temp))
            if (args.Choice=='jwt' or args.Choice=='Jwt' or args.Choice=='JWT'):
                for i in result:
                    temp = Decode_JWT(i.strip())
                    resu.append(temp)
                    print("\033[33m%s\033[0m\033[38m :: \033[0m\033[36m%s\033[0m" % (i.strip('\n') , temp))
        else:
            if (args.Choice == 'url' or args.Choice == 'URL' or args.Choice == 'Url'):
                for i in result:
                    temp = Encode_Url(i.strip())
                    resu.append(temp)
                    print("\033[33m%s\033[0m\033[38m :: \033[0m\033[36m%s\033[0m" % (i.strip('\n') , temp))
            if (args.Choice == 'md5' or args.Choice == 'MD5' or args.Choice == 'Md5'):
                for i in result:
                    temp = Encode_MD5(i.strip())
                    resu.append(temp)
                    print("\033[33m%s\033[0m\033[38m :: \033[0m\033[36m%s\033[0m" % (i.strip('\n') , temp))
            if (args.Choice == 'sha1' or args.Choice == 'SHA1' or args.Choice == 'Sha1'):
                for i in result:
                    temp = Encode_sha1(i.strip())
                    resu.append(temp)
                    print("\033[33m%s\033[0m\033[38m :: \033[0m\033[36m%s\033[0m" % (i.strip('\n') , temp))
            if (args.Choice == 'sha224' or args.Choice == 'SHA224' or args.Choice == 'Sha224'):
                for i in result:
                    temp = Encode_sha224(i.strip())
                    resu.append(temp)
                    print("\033[33m%s\033[0m\033[38m :: \033[0m\033[36m%s\033[0m" % (i.strip('\n') , temp))
            if (args.Choice == 'sha256' or args.Choice == 'SHA256' or args.Choice == 'Sha256'):
                for i in result:
                    temp = Encode_sha256(i.strip())
                    resu.append(temp)
                    print("\033[33m%s\033[0m\033[38m :: \033[0m\033[36m%s\033[0m" % (i.strip('\n') , temp))
            if (args.Choice == 'sha384' or args.Choice == 'SHA384' or args.Choice == 'Sha384'):
                for i in result:
                    temp = Encode_sha384(i.strip())
                    resu.append(temp)
                    print("\033[33m%s\033[0m\033[38m :: \033[0m\033[36m%s\033[0m" % (i.strip('\n') , temp))
            if (args.Choice == 'sha512' or args.Choice == 'SHA512' or args.Choice == 'Sha512'):
                for i in result:
                    temp = Encode_sha512(i.strip())
                    resu.append(temp)
                    print("\033[33m%s\033[0m\033[38m :: \033[0m\033[36m%s\033[0m" % (i.strip('\n') , temp))
            if (args.Choice == 'Unicode' or args.Choice == 'unicode' or args.Choice == 'UNICODE'):
                for i in result:
                    temp = Encode_Unicode(i.strip())
                    resu.append(temp)
                    print("\033[33m%s\033[0m\033[38m :: \033[0m\033[36m%s\033[0m" % (i.strip('\n') , temp))
            if (args.Choice == 'hex' or args.Choice == 'HEX' or args.Choice == 'Hex'):
                for i in result:
                    temp = Encode_Hex(i.strip()).replace("%", "")
                    resu.append(temp)
                    print("\033[33m%s\033[0m\033[38m :: \033[0m\033[36m%s\033[0m" % (i.strip('\n') , temp))
            if (args.Choice == 'Shellcode' or args.Choice == 'shellcode' or args.Choice == 'SHELLCODE'):
                for i in result:
                    temp = Encode_Hex(i.strip()).replace("%", "\\x")
                    resu.append(temp)
                    print("\033[33m%s\033[0m\033[38m :: \033[0m\033[36m%s\033[0m" % (i.strip('\n') , temp))
            if (args.Choice == 'Base64' or args.Choice == 'base64' or args.Choice == 'BASE64'):
                for i in result:
                    temp = Encode_Base64(i.strip())
                    resu.append(temp)
                    print("\033[33m%s\033[0m\033[38m :: \033[0m\033[36m%s\033[0m" % (i.strip('\n') , temp))
            if (args.Choice == 'Base16' or args.Choice == 'base16' or args.Choice == 'BASE16'):
                for i in result:
                    temp = Encode_Base16(i.strip())
                    resu.append(temp)
                    print("\033[33m%s\033[0m\033[38m :: \033[0m\033[36m%s\033[0m" % (i.strip('\n') , temp))
            if (args.Choice == 'Base32' or args.Choice == 'base32' or args.Choice == 'BASE32'):
                for i in result:
                    temp = Encode_Base32(i.strip())
                    resu.append(temp)
                    print("\033[33m%s\033[0m\033[38m :: \033[0m\033[36m%s\033[0m" % (i.strip('\n') , temp))
            if (args.Choice == 'Base85' or args.Choice == 'base85' or args.Choice == 'BASE85'):
                for i in result:
                    temp = Encode_Base85(i.strip())
                    resu.append(temp)
                    print("\033[33m%s\033[0m\033[38m :: \033[0m\033[36m%s\033[0m" % (i.strip('\n') , temp))
            if (args.Choice == 'Html' or args.Choice == 'html' or args.Choice == 'HTML'):
                for i in result:
                    temp = Encode_Html(i.strip())
                    resu.append(temp)
                    print("\033[33m%s\033[0m\033[38m :: \033[0m\033[36m%s\033[0m" % (i.strip('\n') , temp))
            if (args.Choice == 'Time' or args.Choice == 'time' or args.Choice == 'TIME'):
                for i in result:
                    temp = Encode_Time(i.strip())
                    resu.append(temp)
                    print("\033[33m%s\033[0m\033[38m :: \033[0m\033[36m%s\033[0m" % (i.strip('\n') , temp))
            if (args.Choice=='DES' or args.Choice=='des' or args.Choice=='Des'):
                for i in result:
                    temp = Encode_Des(i.strip(), args.KEY, args.IV, args.edmode, args.result)
                    resu.append(temp)
                    print("\033[33m%s\033[0m\033[38m :: \033[0m\033[36m%s\033[0m" % (i.strip('\n') , temp))
            if (args.Choice=='AES' or args.Choice=='aes' or args.Choice=='Aes'):
                for i in result:
                    temp = Encode_AES(i.strip(), args.KEY, args.IV, args.edmode, args.result)
                    resu.append(temp)
                    print("\033[33m%s\033[0m\033[38m :: \033[0m\033[36m%s\033[0m" % (i.strip('\n') , temp))
            if (args.Choice=='jwt' or args.Choice=='Jwt' or args.Choice=='JWT'):
                for i in result:
                    temp = Encode_JWT(i.strip(), args.KEY, args.edmode)
                    resu.append(temp)
                    print("\033[33m%s\033[0m\033[38m :: \033[0m\033[36m%s\033[0m" % (i.strip('\n') , temp))
        if args.output:
            SavefilePath = args.output
        else:
            SavefilePath = 'result/' + args.Choice +'.txt'
        print("\033[31m结果保存在       |      \033[0m\033[31m%s\033[0m" %SavefilePath)
        Write_File(resu, SavefilePath)
