from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
import os


my_path = os.path.abspath(os.getcwd())
path_file_publ = my_path + "/public-rsa.pem"
path_file_priv = my_path + "/private-rsa.pem"

print("Ruta del archivo de clave pública:", path_file_publ)
print("Ruta del archivo de clave privada:", path_file_priv)

try:
    key_priv = RSA.import_key(open(path_file_priv).read())
    key_publ = RSA.import_key(open(path_file_publ).read())
except Exception as e:
    print("Error al cargar las claves:", str(e))
    exit()