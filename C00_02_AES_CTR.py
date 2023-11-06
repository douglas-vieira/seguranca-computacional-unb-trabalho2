from C00_01_AES_EBC import *

def enc_ctr(chave, dados, nonce, num_rounds):
    tamanho_bloco = 16  # Tamanho do bloco AES em bytes

    dados_cifrados = b""
    contador = 0

    while contador * tamanho_bloco < len(dados):
        bytes_contador = contador.to_bytes(16, 'big')
        keystream = enc(chave, nonce + bytes_contador, num_rounds)
        bloco = dados[contador * tamanho_bloco:(contador + 1) * tamanho_bloco]
        bloco_cifrado = xor_bytes(bloco, keystream)
        dados_cifrados += bloco_cifrado
        contador += 1

    return dados_cifrados

def dec_ctr(chave, dados_cifrados, nonce, num_rounds):
    return enc_ctr(chave, dados_cifrados, nonce, num_rounds)