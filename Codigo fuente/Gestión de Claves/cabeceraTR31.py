from psec import tr31

#Documentado en este fichero
#https://github.com/knovichikhin/psec/blob/master/psec/tr31.py

header, key = tr31.unwrap( kbpk=bytes.fromhex("A1A10101010101010101010101010103"), key_block="D0144D0AB00S000061653A93F145CA939753BAADE92C5BB69523F8D15EA97FE416BF3AA266F69626488B2A66F2D21F44AEC1DF879068B802F13FB925CB4773D70D861DA2C9D75D30")
print(key.hex())

print("Key Version ID: " + header.version_id )
print("Algoritmo: " + header.algorithm)
print("Modo de uso: " + header.mode_of_use)
print("Uso de la clave: " + header.key_usage)
print("Exportabilidad: " + header.exportability)