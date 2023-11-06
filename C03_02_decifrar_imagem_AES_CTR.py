from C00_01_AES_EBC import *
from C00_02_AES_CTR import *

def decifrar_imagem(num_rounds):
    # Ler arquivo como bytes
    with open("imagem_"+"cifrada_"+str(num_rounds)+".png", "rb") as arquivo:
        conteudo = arquivo.read()
        foto = bytearray(conteudo)

    # Chave AES de 128 bits (16 bytes) e valor do nonce
    key        = b'1234567891234567'
    nonce      = b'abcdefghijklmnop'
    
    # DesCriptografar os dados usando o modo AES ECB
    foto = dec_ctr(key, foto, nonce, num_rounds)

    # Salvar os bytes descriptografados em um arquivo
    with open("imagem_"+"decifrada_"+str(num_rounds)+".png", "wb") as arquivo:
        f = arquivo.write(foto)
        
decifrar_imagem(1)  # cifração com 1  round
decifrar_imagem(5)  # cifração com 5  rounds
decifrar_imagem(9)  # cifração com 9  rounds
decifrar_imagem(10) # cifração com 10 rounds
decifrar_imagem(11) # cifração com 11 rounds