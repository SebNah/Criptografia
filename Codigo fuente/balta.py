import json
from base64 import b64encode, b64decode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

textoParaCifrar_bytes = bytes('He descubierto el error y no volveré a hacerlo mal', 'UTF-8')


clave = bytes.fromhex('E2CFF885901B3449E9C448BA5B948A8C4EE322152B3F1ACFA0148FB3A426DB74')


nonce = b64decode('9Yccn/f5nJJhAt2S')
cipher = AES.new(clave, AES.MODE_GCM,nonce=nonce)


texto_cifrado_bytes, tag = cipher.encrypt_and_digest(textoParaCifrar_bytes)
nonce_b64 = b64encode(cipher.nonce).decode('utf-8')
texto_cifrado_b64 = b64encode(texto_cifrado_bytes).decode('utf-8')
mensaje_json = json.dumps({'nonce':nonce_b64, 'texto cifrado':texto_cifrado_b64})
print(mensaje_json)


#B64 balta = Xcu2Jh0PuinOOUMemgE7NMvKKk4Euy2QFJ1h9K/QTWXiq92dhLum64MHCV9QePv8FiVt

#b64 = Xcu2Jh0PuinOOUMemgE7NMvKKk4Euy2QFJ1h9K/QTWXiq92dhLum64MHCV9QePv8FiVt

