from C00_01_AES_EBC import *

# Ler arquivo como bytes
with open("04_02_texto_cifrado.txt", "rb") as arquivo:
    conteudo = arquivo.read()
    texto = bytearray(conteudo)

# Chave AES de 128 bits (16 bytes) e valor do nonce
key        = b'1234567891234567'
num_rounds = 10

# Criptografar os dados usando o modo AES ECB
texto = dec(key, texto, num_rounds)

# Salvar os bytes de-criptografados em um arquivo
with open("04_03_texto_decifrado.txt", "wb") as arquivo:
    f = arquivo.write(texto)