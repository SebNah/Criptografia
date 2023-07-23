#ejercicio 15
from psec import tr31

#Documentado en este fichero
#https://github.com/knovichikhin/psec/blob/master/psec/tr31.py

header, key = tr31.unwrap( kbpk=bytes.fromhex("A1A10101010101010101010101010102"), key_block="D0144D0AB00S000042766B9265B2DF93AE6E29B58135B77A2F616C8D515ACDBE6A5626F79FA7B4071E9EE1423C6D7970FA2B965D18B23922B5B2E5657495E03CD857FD37018E111B")
print(key.hex())

print("Key Version ID: " + header.version_id )
print("Algoritmo: " + header.algorithm)
print("Modo de uso: " + header.mode_of_use)
print("Uso de la clave: " + header.key_usage)
print("Exportabilidad: " + header.exportability)



#¿Con qué algoritmo se ha protegido el bloque de clave?
#algoritmo de tipo AES
#¿Para qué algoritmo se ha definido la clave?
#algoritmo de tipo AES
#¿Para qué modo de uso se ha generado?
#Se genero la clave para cifrar y descifrar
#¿Es exportable?
#Si pero es sensible, exportable solo bajo clave no confiable
#¿Para qué se puede usar la clave?
#Es una clave simetrica que se puede usar para cifrar y descifrar datos.
#¿Qué valor tiene la clave?
#c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1