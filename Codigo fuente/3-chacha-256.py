from Crypto.Cipher import ChaCha20
from base64 import b64decode, b64encode
from Crypto.Random import get_random_bytes
import json
import jks
import os

try:
    textoPlano = bytes('KeepCoding te enseña a codificar y a cifrar', 'UTF-8')   
    
    #Recuperando la clave
    path = os.path.dirname(__file__)
    keystore = path + "/KeyStorePracticas"
    ks = jks.KeyStore.load(keystore, "123456")

    for alias, sk in ks.secret_keys.items():
        if sk.alias == "cifrado-sim-chacha20-256":
            key = sk.key

    #Mostrando la clave en hexadecimal
    print("La clave es:", key.hex())
   
    #El nonce deberia ser random, esa es su funcion principal
    #nonce_mensaje = get_random_bytes(12)
    nonce_mensaje = b64decode("9Yccn/f5nJJhAt2S")   

    #configuramos cifrador y ciframos 
    cipher = ChaCha20.new(key=key, nonce=nonce_mensaje)    
    texto_cifrado= cipher.encrypt(textoPlano) 

    #Imprimimos el texto cifrado  
    print(b64encode(texto_cifrado).decode())

    #Creamos un JSON y lo enviamos mostrando su contenido 
    mensaje_enviado = { "nonce": b64encode(nonce_mensaje).decode(), "texto cifrado": b64encode(texto_cifrado).decode()}
    json_mensaje = json.dumps(mensaje_enviado)
    print("Mensaje: ", json_mensaje)

    #Descifrado...
    decipher = ChaCha20.new(key=key, nonce=b64decode(mensaje_enviado["nonce"]))
    plaintext = decipher.decrypt(b64decode(mensaje_enviado["texto cifrado"]))
    print('Datos cifrados en claro = ', plaintext.decode('utf-8'))

except (ValueError, KeyError) as error: 
    print("Problemas....")
    print("El motivo del error es: ", error)



