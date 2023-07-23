import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

#Cifrado
textoPlano_bytes = bytes.fromhex('00000000000000000000000000000000')
clave = bytes.fromhex('A2CFF885901A5449E9C448BA5B948A8C4EE377152B3F1ACFA0148FB3A426DB72')
iv_bytes = bytes.fromhex('00000000000000000000000000000000')
cipher = AES.new(clave, AES.MODE_CBC,iv_bytes)
texto_cifrado_bytes = cipher.encrypt(pad(textoPlano_bytes, AES.block_size,  style='pkcs7'))
print("Cifrado AES:", texto_cifrado_bytes.hex())
print("KCV AES:", texto_cifrado_bytes.hex()[0:6])


m = hashlib.sha256()
m.update(bytes.fromhex("A2CFF885901A5449E9C448BA5B948A8C4EE377152B3F1ACFA0148FB3A426DB72"))
print("Cifrado SHA256: " + m.digest().hex())
print("KCV SHA256: " + m.digest().hex()[0:6])

