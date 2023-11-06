from C00_01_AES_EBC import *

# Ler arquivo como bytes
with open("04_01_texto_para_cifrar.txt", "rb") as arquivo:
    conteudo = arquivo.read()
    texto = bytearray(conteudo)

# Chave AES de 128 bits (16 bytes) e valor do nonce
key        = b'1234567891234567'
num_rounds = 10

# Criptografar os dados usando o modo AES ECB
texto = enc(key, texto, num_rounds)

# Salvar os bytes criptografados em um arquivo
with open("04_02_texto_cifrado.txt", "wb") as arquivo:
    f = arquivo.write(texto)