from Crypto.Cipher import ChaCha20
from Crypto.Random import get_random_bytes

def generate_key():
    return get_random_bytes(32) 

def encrypt(plain_text, key):
    cipher = ChaCha20.new(key=key)
    nonce = cipher.nonce 
    encrypted_bytes = cipher.encrypt(plain_text.encode())
    
    return nonce + encrypted_bytes 

def decrypt(encrypted_data, key):
    nonce = encrypted_data[:8]  
    encrypted_bytes = encrypted_data[8:] 
    
    cipher = ChaCha20.new(key=key, nonce=nonce)
    decrypted_text = cipher.decrypt(encrypted_bytes).decode()
    
    return decrypted_text

key = generate_key()
text = input("Masukkan teks yang ingin dienkripsi: ")

encrypted = encrypt(text, key)
print("Hasil Enkripsi:", encrypted.hex())

decrypted = decrypt(encrypted, key)
print("Hasil Dekripsi:", decrypted)
