from Crypto.Hash import HMAC, SHA256
import jks
import os


def getHMAC(key_bytes,data_bytes):
    hmac256 = HMAC.new(key_bytes, msg=data_bytes, digestmod=SHA256)
    return hmac256.hexdigest()

def validateHMAC(key_bytes,data_bytes,hmac):
    hmac256 = HMAC.new(key_bytes,msg=data_bytes,digestmod=SHA256)
    result = "KO"
    try:
        hmac256.hexverify(hmac)
        result = "OK"
    except ValueError:
        result = "KO"
    print("result: " + result)
    return result


# Recuperando la clave
path = os.path.dirname(__file__)
keystore = path + "/KeyStorePracticas"
ks = jks.KeyStore.load(keystore, "123456")
for alias, sk in ks.secret_keys.items():
    if sk.alias == "hmac-sha256":
        key = sk.key
print("La clave es:", key.hex())

#CIFRANDO
clave_bytes = bytes.fromhex(key.hex())
datos = bytes("Siempre existe más de una forma de hacerlo, y más de una solución válida.", "utf8")
hmac = getHMAC(clave_bytes,datos)

print(hmac)
print(validateHMAC(clave_bytes, datos,hmac))
