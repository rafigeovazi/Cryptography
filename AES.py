from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64

def generate_key():
    return b'This is a key123' 

def encrypt(plain_text, key):
    cipher = AES.new(key, AES.MODE_CBC, iv=key)
    encrypted_bytes = cipher.encrypt(pad(plain_text.encode(), AES.block_size))
    return base64.b64encode(encrypted_bytes).decode()

def decrypt(encrypted_text, key):
    cipher = AES.new(key, AES.MODE_CBC, iv=key)
    decrypted_bytes = unpad(cipher.decrypt(base64.b64decode(encrypted_text)), AES.block_size)
    return decrypted_bytes.decode()

if __name__ == "__main__":
    key = generate_key()
    user_input = input("Masukkan teks yang ingin dienkripsi: ")
    encrypted_text = encrypt(user_input, key)
    print("Teks terenkripsi:", encrypted_text)
    
    decrypted_text = decrypt(encrypted_text, key)
    print("Teks setelah dekripsi:", decrypted_text)
