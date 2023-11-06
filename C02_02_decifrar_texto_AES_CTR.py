from C00_01_AES_EBC import *
from C00_02_AES_CTR import *

# Ler arquivo como bytes
with open("05_02_texto_cifrado_CTR.txt", "rb") as arquivo:
    conteudo = arquivo.read()
    texto = bytearray(conteudo)

# Chave AES de 128 bits (16 bytes) e valor do nonce
key        = b'1234567891234567'
nonce      = b'abcdefghijklmnop'
num_rounds = 10

# Des-Criptografar os dados usando o modo AES CTR
texto = dec_ctr(key, texto, nonce, num_rounds)

# Salvar os bytes criptografados em um arquivo
with open("05_03_texto_decifrado_CTR.txt", "wb") as arquivo:
    f = arquivo.write(texto)
