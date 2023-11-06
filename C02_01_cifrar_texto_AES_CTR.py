from C00_01_AES_EBC import *
from C00_02_AES_CTR import *

# Ler arquivo como bytes
with open("05_01_texto_para_cifrar_CTR.txt", "rb") as arquivo:
    conteudo = arquivo.read()
    texto = bytearray(conteudo)

# Chave AES de 128 bits (16 bytes) e valor do nonce
key        = b'1234567891234567'
nonce      = b'abcdefghijklmnop'
num_rounds = 10

# Criptografar os dados usando o modo AES ECB
texto = enc_ctr(key, texto, nonce, num_rounds)

# Salvar os bytes criptografados em um arquivo
with open("05_02_texto_cifrado_CTR.txt", "wb") as arquivo:
    f = arquivo.write(texto)