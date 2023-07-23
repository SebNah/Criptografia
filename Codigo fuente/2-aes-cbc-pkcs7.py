from base64 import  b64decode
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad, pad
import jks
import os


#Lamado a clave
path = os.path.dirname(__file__)

keystore = path + "/KeyStorePracticas"


ks = jks.KeyStore.load(keystore, "123456")

for alias, sk in ks.secret_keys.items():
    if sk.alias == "cifrado-sim-aes-256":
        key = sk.key

print("La clave es:", key.hex())


#Descifrado

try:
    iv_desc_bytes = bytes.fromhex('00000000000000000000000000000000')
    texto_cifrado_bytes = b64decode('TQ9SOMKc6aFS9SlxhfK9wT18UXpPCd505Xf5J/5nLI7Of/o0QKIWXg3nu1RRz4QWElezdrLAD5LO4USt3aB/i50nvvJbBiG+le1ZhpR84oI=')
    cipher = AES.new(key, AES.MODE_CBC, iv_desc_bytes)

    mensaje_des_bytes = unpad(cipher.decrypt(texto_cifrado_bytes), AES.block_size, style="pkcs7")

    print("El texto en claro es: ", mensaje_des_bytes.decode("utf-8"))
    print(texto_cifrado_bytes.hex())
    

except (ValueError, KeyError) as error:
    print('Problemas para descifrar....')
    print("El motivo del error es: ", error) 