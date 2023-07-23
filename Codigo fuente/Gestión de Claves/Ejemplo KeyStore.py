import jks
import os

# Obteniendo el path
path = os.path.dirname(__file__)

keystore = path + "/KeyStoreEjemplo"


ks = jks.KeyStore.load(keystore, "123456")

for alias, sk in ks.secret_keys.items():
    if sk.alias == "cifrado-sim-aes-256":
        key = sk.key

print("La clave es:", key.hex())

# 