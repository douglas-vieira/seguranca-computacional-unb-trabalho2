from C00_01_AES_EBC import *
from C00_02_AES_CTR import *

def cifrar_imagem(num_rounds):
    # Ler arquivo como bytes
    with open("imagem.png", "rb") as arquivo:
        conteudo = arquivo.read()
        foto = bytearray(conteudo)

    # Chave AES de 128 bits (16 bytes) e valor do nonce
    key        = b'1234567891234567'
    nonce      = b'abcdefghijklmnop'
    
    # Criptografar os dados usando o modo AES ECB
    foto = enc_ctr(key, foto, nonce, num_rounds)

    # Salvar os bytes criptografados em um arquivo
    with open("imagem_"+"cifrada_"+str(num_rounds)+".png", "wb") as arquivo:
        f = arquivo.write(foto)


cifrar_imagem(1)  # cifração com 1  round
cifrar_imagem(5)  # cifração com 5  rounds
cifrar_imagem(9)  # cifração com 9  rounds
cifrar_imagem(10) # cifração com 10 rounds
cifrar_imagem(11) # cifração com 11 rounds