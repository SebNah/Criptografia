from psec import tr31


def importar():
    kbpk_b = bytes.fromhex("A1A10101010101010101010101010103")
    kb = "D0144D0AB00S000061653A93F145CA939753BAADE92C5BB69523F8D15EA97FE416BF3AA266F69626488B2A66F2D21F44AEC1DF879068B802F13FB925CB4773D70D861DA2C9D75D30"
    MykeyBlock =tr31.KeyBlock(kbpk_b).unwrap(kb).hex()
    print("Importar Clave:" + tr31.KeyBlock(kbpk_b).unwrap(kb).hex())
    print("Mode use:" + tr31.KeyBlock(MykeyBlock).header.mode_of_use)
   # print("Header: "+ str(MykeyBlock.header))


def exportar():
    h = tr31.Header()
    h.version_id = "D"
    h.key_usage = "D0"
    h.algorithm = "A"
    h.mode_of_use = "B"
    h.exportability = "S"

    kbpk = bytes.fromhex("A1A10101010101010101010101010103")
    key = bytes.fromhex("c2c1c1c1c1c1c1c1c1c1c1c1c1c1c1c2")
    kb = tr31.KeyBlock(kbpk, h)
    print("Fase de Exportación: " + kb.wrap(key))


if __name__ == "__main__":
    exportar()
    importar()
    #exportar()
