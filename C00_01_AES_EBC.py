# Função para dividir uma sequência de bytes em matrizes de 4x4 bytes (blocos de 16 bytes)
def quebrar_em_blocos_de_16(s):
    todos = []
    for i in range(len(s)//16):
        b = s[i*16: i*16 + 16]
        matriz = [[], [], [], []]
        for i in range(4):
            for j in range(4):
                matriz[i].append(b[i + j*4])
        todos.append(matriz)
    return todos

# Tabela S-Box usada na etapa de substituição da cifragem AES
aes_sbox = [
    [int('63', 16), int('7c', 16), int('77', 16), int('7b', 16), int('f2', 16), int('6b', 16), int('6f', 16), int('c5', 16), int('30', 16), int('01', 16), int('67', 16), int('2b', 16), int('fe', 16), int('d7', 16), int('ab', 16), int('76', 16)],
    [int('ca', 16), int('82', 16), int('c9', 16), int('7d', 16), int('fa', 16), int('59', 16), int('47', 16), int('f0', 16), int('ad', 16), int('d4', 16), int('a2', 16), int('af', 16), int('9c', 16), int('a4', 16), int('72', 16), int('c0', 16)],
    [int('b7', 16), int('fd', 16), int('93', 16), int('26', 16), int('36', 16), int('3f', 16), int('f7', 16), int('cc', 16), int('34', 16), int('a5', 16), int('e5', 16), int('f1', 16), int('71', 16), int('d8', 16), int('31', 16), int('15', 16)],
    [int('04', 16), int('c7', 16), int('23', 16), int('c3', 16), int('18', 16), int('96', 16), int('05', 16), int('9a', 16), int('07', 16), int('12', 16), int('80', 16), int('e2', 16), int('eb', 16), int('27', 16), int('b2', 16), int('75', 16)],
    [int('09', 16), int('83', 16), int('2c', 16), int('1a', 16), int('1b', 16), int('6e', 16), int('5a', 16), int('a0', 16), int('52', 16), int('3b', 16), int('d6', 16), int('b3', 16), int('29', 16), int('e3', 16), int('2f', 16), int('84', 16)],
    [int('53', 16), int('d1', 16), int('00', 16), int('ed', 16), int('20', 16), int('fc', 16), int('b1', 16), int('5b', 16), int('6a', 16), int('cb', 16), int('be', 16), int('39', 16), int('4a', 16), int('4c', 16), int('58', 16), int('cf', 16)],
    [int('d0', 16), int('ef', 16), int('aa', 16), int('fb', 16), int('43', 16), int('4d', 16), int('33', 16), int('85', 16), int('45', 16), int('f9', 16), int('02', 16), int('7f', 16), int('50', 16), int('3c', 16), int('9f', 16), int('a8', 16)],
    [int('51', 16), int('a3', 16), int('40', 16), int('8f', 16), int('92', 16), int('9d', 16), int('38', 16), int('f5', 16), int('bc', 16), int('b6', 16), int('da', 16), int('21', 16), int('10', 16), int('ff', 16), int('f3', 16), int('d2', 16)],
    [int('cd', 16), int('0c', 16), int('13', 16), int('ec', 16), int('5f', 16), int('97', 16), int('44', 16), int('17', 16), int('c4', 16), int('a7', 16), int('7e', 16), int('3d', 16), int('64', 16), int('5d', 16), int('19', 16), int('73', 16)],
    [int('60', 16), int('81', 16), int('4f', 16), int('dc', 16), int('22', 16), int('2a', 16), int('90', 16), int('88', 16), int('46', 16), int('ee', 16), int('b8', 16), int('14', 16), int('de', 16), int('5e', 16), int('0b', 16), int('db', 16)],
    [int('e0', 16), int('32', 16), int('3a', 16), int('0a', 16), int('49', 16), int('06', 16), int('24', 16), int('5c', 16), int('c2', 16), int('d3', 16), int('ac', 16), int('62', 16), int('91', 16), int('95', 16), int('e4', 16), int('79', 16)],
    [int('e7', 16), int('c8', 16), int('37', 16), int('6d', 16), int('8d', 16), int('d5', 16), int('4e', 16), int('a9', 16), int('6c', 16), int('56', 16), int('f4', 16), int('ea', 16), int('65', 16), int('7a', 16), int('ae', 16), int('08', 16)],
    [int('ba', 16), int('78', 16), int('25', 16), int('2e', 16), int('1c', 16), int('a6', 16), int('b4', 16), int('c6', 16), int('e8', 16), int('dd', 16), int('74', 16), int('1f', 16), int('4b', 16), int('bd', 16), int('8b', 16), int('8a', 16)],
    [int('70', 16), int('3e', 16), int('b5', 16), int('66', 16), int('48', 16), int('03', 16), int('f6', 16), int('0e', 16), int('61', 16), int('35', 16), int('57', 16), int('b9', 16), int('86', 16), int('c1', 16), int('1d', 16), int('9e', 16)],
    [int('e1', 16), int('f8', 16), int('98', 16), int('11', 16), int('69', 16), int('d9', 16), int('8e', 16), int('94', 16), int('9b', 16), int('1e', 16), int('87', 16), int('e9', 16), int('ce', 16), int('55', 16), int('28', 16), int('df', 16)],
    [int('8c', 16), int('a1', 16), int('89', 16), int('0d', 16), int('bf', 16), int('e6', 16), int('42', 16), int('68', 16), int('41', 16), int('99', 16), int('2d', 16), int('0f', 16), int('b0', 16), int('54', 16), int('bb', 16), int('16', 16)]
]

# Tabela S-Box reversa usada na etapa de substituição da decifragem AES
reverse_aes_sbox = [
    [int('52', 16), int('09', 16), int('6a', 16), int('d5', 16), int('30', 16), int('36', 16), int('a5', 16), int('38', 16), int('bf', 16), int('40', 16), int('a3', 16), int('9e', 16), int('81', 16), int('f3', 16), int('d7', 16), int('fb', 16)],
    [int('7c', 16), int('e3', 16), int('39', 16), int('82', 16), int('9b', 16), int('2f', 16), int('ff', 16), int('87', 16), int('34', 16), int('8e', 16), int('43', 16), int('44', 16), int('c4', 16), int('de', 16), int('e9', 16), int('cb', 16)],
    [int('54', 16), int('7b', 16), int('94', 16), int('32', 16), int('a6', 16), int('c2', 16), int('23', 16), int('3d', 16), int('ee', 16), int('4c', 16), int('95', 16), int('0b', 16), int('42', 16), int('fa', 16), int('c3', 16), int('4e', 16)],
    [int('08', 16), int('2e', 16), int('a1', 16), int('66', 16), int('28', 16), int('d9', 16), int('24', 16), int('b2', 16), int('76', 16), int('5b', 16), int('a2', 16), int('49', 16), int('6d', 16), int('8b', 16), int('d1', 16), int('25', 16)],
    [int('72', 16), int('f8', 16), int('f6', 16), int('64', 16), int('86', 16), int('68', 16), int('98', 16), int('16', 16), int('d4', 16), int('a4', 16), int('5c', 16), int('cc', 16), int('5d', 16), int('65', 16), int('b6', 16), int('92', 16)],
    [int('6c', 16), int('70', 16), int('48', 16), int('50', 16), int('fd', 16), int('ed', 16), int('b9', 16), int('da', 16), int('5e', 16), int('15', 16), int('46', 16), int('57', 16), int('a7', 16), int('8d', 16), int('9d', 16), int('84', 16)],
    [int('90', 16), int('d8', 16), int('ab', 16), int('00', 16), int('8c', 16), int('bc', 16), int('d3', 16), int('0a', 16), int('f7', 16), int('e4', 16), int('58', 16), int('05', 16), int('b8', 16), int('b3', 16), int('45', 16), int('06', 16)],
    [int('d0', 16), int('2c', 16), int('1e', 16), int('8f', 16), int('ca', 16), int('3f', 16), int('0f', 16), int('02', 16), int('c1', 16), int('af', 16), int('bd', 16), int('03', 16), int('01', 16), int('13', 16), int('8a', 16), int('6b', 16)],
    [int('3a', 16), int('91', 16), int('11', 16), int('41', 16), int('4f', 16), int('67', 16), int('dc', 16), int('ea', 16), int('97', 16), int('f2', 16), int('cf', 16), int('ce', 16), int('f0', 16), int('b4', 16), int('e6', 16), int('73', 16)],
    [int('96', 16), int('ac', 16), int('74', 16), int('22', 16), int('e7', 16), int('ad', 16), int('35', 16), int('85', 16), int('e2', 16), int('f9', 16), int('37', 16), int('e8', 16), int('1c', 16), int('75', 16), int('df', 16), int('6e', 16)],
    [int('47', 16), int('f1', 16), int('1a', 16), int('71', 16), int('1d', 16), int('29', 16), int('c5', 16), int('89', 16), int('6f', 16), int('b7', 16), int('62', 16), int('0e', 16), int('aa', 16), int('18', 16), int('be', 16), int('1b', 16)],
    [int('fc', 16), int('56', 16), int('3e', 16), int('4b', 16), int('c6', 16), int('d2', 16), int('79', 16), int('20', 16), int('9a', 16), int('db', 16), int('c0', 16), int('fe', 16), int('78', 16), int('cd', 16), int('5a', 16), int('f4', 16)],
    [int('1f', 16), int('dd', 16), int('a8', 16), int('33', 16), int('88', 16), int('07', 16), int('c7', 16), int('31', 16), int('b1', 16), int('12', 16), int('10', 16), int('59', 16), int('27', 16), int('80', 16), int('ec', 16), int('5f', 16)],
    [int('60', 16), int('51', 16), int('7f', 16), int('a9', 16), int('19', 16), int('b5', 16), int('4a', 16), int('0d', 16), int('2d', 16), int('e5', 16), int('7a', 16), int('9f', 16), int('93', 16), int('c9', 16), int('9c', 16), int('ef', 16)],
    [int('a0', 16), int('e0', 16), int('3b', 16), int('4d', 16), int('ae', 16), int('2a', 16), int('f5', 16), int('b0', 16), int('c8', 16), int('eb', 16), int('bb', 16), int('3c', 16), int('83', 16), int('53', 16), int('99', 16), int('61', 16)],
    [int('17', 16), int('2b', 16), int('04', 16), int('7e', 16), int('ba', 16), int('77', 16), int('d6', 16), int('26', 16), int('e1', 16), int('69', 16), int('14', 16), int('63', 16), int('55', 16), int('21', 16), int('0c', 16), int('7d', 16)]

]

# Função para realizar uma substituição em uma tabela S-Box (S-Box AES)
def consultar(byte):
    x = byte >> 4
    y = byte & 15
    return aes_sbox[x][y]

# Função para realizar uma substituição reversa em uma tabela S-Box (S-Box reversa AES)
def consultar_reversa(byte):
    x = byte >> 4
    y = byte & 15
    return reverse_aes_sbox[x][y]

# Função para expandir a chave original em subchaves para cada rodada
def expandir_chave(chave, num_rodadas):
    rcon = [[1, 0, 0, 0]]

    for _ in range(1, num_rodadas):
        rcon.append([rcon[-1][0] * 2, 0, 0, 0])
        if rcon[-1][0] > 0x80:
            rcon[-1][0] ^= 0x11b

    chave_grid = quebrar_em_blocos_de_16(chave)[0]

    for rodada in range(num_rodadas):
        ultima_coluna = [linha[-1] for linha in chave_grid]
        ultima_coluna_rotacionada = rotacionar_linha_esquerda(ultima_coluna)
        ultima_coluna_substituida = [consultar(b) for b in ultima_coluna_rotacionada]
        ultima_coluna_rcon = [ultima_coluna_substituida[i] ^ rcon[rodada][i] for i in range(len(ultima_coluna_rotacionada))]

        for r in range(4):
            chave_grid[r] += bytes([ultima_coluna_rcon[r] ^ chave_grid[r][rodada * 4]])

        for i in range(len(chave_grid)):
            for j in range(1, 4):
                chave_grid[i] += bytes([chave_grid[i][rodada * 4 + j] ^ chave_grid[i][rodada * 4 + j + 3]])

    return chave_grid

# Função para realizar uma rotação à esquerda em uma linha de uma matriz de bytes
def rotacionar_linha_esquerda(linha, n=1):
    return linha[n:] + linha[:n]

# Função para multiplicar um byte por 2
def multiplicar_por_2(v):
    s = v << 1
    s &= 0xff
    if (v & 128) != 0:
        s = s ^ 0x1b
    return s

# Função para multiplicar um byte por 3
def multiplicar_por_3(v):
    return multiplicar_por_2(v) ^ v

# Função para realizar a mistura de colunas em uma matriz de estado
def misturar_colunas(matriz):
    nova_matriz = [[], [], [], []]
    for i in range(4):
        coluna = [matriz[j][i] for j in range(4)]
        coluna = misturar_coluna(coluna)
        for i in range(4):
            nova_matriz[i].append(coluna[i])
    return nova_matriz

# Função para realizar a mistura de colunas em uma única coluna
def misturar_coluna(coluna):
    r = [
        multiplicar_por_2(coluna[0]) ^ multiplicar_por_3(coluna[1]) ^ coluna[2] ^ coluna[3],
        multiplicar_por_2(coluna[1]) ^ multiplicar_por_3(coluna[2]) ^ coluna[3] ^ coluna[0],
        multiplicar_por_2(coluna[2]) ^ multiplicar_por_3(coluna[3]) ^ coluna[0] ^ coluna[1],
        multiplicar_por_2(coluna[3]) ^ multiplicar_por_3(coluna[0]) ^ coluna[1] ^ coluna[2],
    ]
    return r

# Função para adicionar a subchave a uma matriz de estado
def adicionar_subchave(matriz_estado, chave):
    r = []

    # 4 linhas no grid
    for i in range(4):
        r.append([])
        # 4 valores em cada linha
        for j in range(4):
            r[-1].append(matriz_estado[i][j] ^ chave[i][j])
    return r

# Função para extrair a subchave para uma rodada específica
def extrair_subchave_para_rodada(chave_expandida, rodada):
  return [linha[rodada*4: rodada*4 + 4] for linha in chave_expandida]

# Função para inverter a ordem dos bytes em um objeto de bytes
def inverter_bytes(byte_obj):
    bytes_invertidos = byte_obj[::-1]
    return bytes_invertidos

# Função para realizar a operação de XOR bit a bit em duas sequências de bytes
def xor_bytes(b1, b2):
    return bytes(x ^ y for x, y in zip(b1, b2))

# Função para realizar a cifragem AES no modo ECB
def enc(chave, dados, num_rodadas):
    preenchimento = bytes(16 - len(dados) % 16)

    if len(preenchimento) != 16:
        dados += preenchimento
    blocos = quebrar_em_blocos_de_16(dados)
    
    chave_expandida = expandir_chave(chave, num_rodadas)
    blocos_temp = []
    chave_rodada = extrair_subchave_para_rodada(chave_expandida, 0)

    for bloco in blocos:
        blocos_temp.append(adicionar_subchave(bloco, chave_rodada))

    blocos = blocos_temp

    for rodada in range(1, num_rodadas):
        blocos_temp = []

        for bloco in blocos:
            sub_bytes_step = [[consultar(val) for val in linha] for linha in bloco]
            shift_rows_step = [rotacionar_linha_esquerda(sub_bytes_step[i], i) for i in range(4)]
            misturar_colunas_step = misturar_colunas(shift_rows_step)
            chave_rodada = extrair_subchave_para_rodada(chave_expandida, rodada)
            adicionar_subchave_step = adicionar_subchave(misturar_colunas_step, chave_rodada)
            blocos_temp.append(adicionar_subchave_step)

        blocos = blocos_temp

    blocos_temp = []
    chave_rodada = extrair_subchave_para_rodada(chave_expandida, num_rodadas)

    for bloco in blocos:
        sub_bytes_step = [[consultar(val) for val in linha] for linha in bloco]
        shift_rows_step = [rotacionar_linha_esquerda(sub_bytes_step[i], i) for i in range(4)]
        adicionar_subchave_step = adicionar_subchave(shift_rows_step, chave_rodada)
        blocos_temp.append(adicionar_subchave_step)

    blocos = blocos_temp

    int_stream = []

    for bloco in blocos:
        for coluna in range(4):
            for linha in range(4):
                int_stream.append(bloco[linha][coluna])

    return bytes(int_stream)

# Função para realizar a decifragem AES no modo ECB
def dec(chave, dados):

    blocos = quebrar_em_blocos_de_16(dados)
    chave_expandida = expandir_chave(chave, 11)
    blocos_temp = []
    chave_rodada = extrair_subchave_para_rodada(chave_expandida, 10)

    blocos_temp = []

    for bloco in blocos:

        adicionar_subchave_step = adicionar_subchave(bloco, chave_rodada)
        shift_rows_step = [rotacionar_linha_esquerda(
            adicionar_subchave_step[i], -1 * i) for i in range(4)]
        sub_bytes_step = [[consultar_reversa(val) for val in linha]
                          for linha in shift_rows_step]
        blocos_temp.append(sub_bytes_step)

    blocos = blocos_temp

    for rodada in range(9, 0, -1):
        blocos_temp = []

        for bloco in blocos:
            chave_rodada = extrair_subchave_para_rodada(chave_expandida, rodada)
            adicionar_subchave_step = adicionar_subchave(bloco, chave_rodada)

            # realizar o  mix columns 3 vezes é equivalente a usar a matriz inversa
            misturar_coluna_step = misturar_colunas(adicionar_subchave_step)
            misturar_coluna_step = misturar_colunas(misturar_coluna_step)
            misturar_coluna_step = misturar_colunas(misturar_coluna_step)
            shift_rows_step = [rotacionar_linha_esquerda(
                misturar_coluna_step[i], -1 * i) for i in range(4)]
            sub_bytes_step = [
                [consultar_reversa(val) for val in linha] for linha in shift_rows_step]
            blocos_temp.append(sub_bytes_step)

        blocos = blocos_temp
        blocos_temp = []

    # invertendo a primeira subchave adicionada 
    chave_rodada = extrair_subchave_para_rodada(chave_expandida, 0)

    for bloco in blocos:
        blocos_temp.append(adicionar_subchave(bloco, chave_rodada))

    blocos = blocos_temp

    # grid para bytes
    int_stream = []
    for bloco in blocos:
        for coluna in range(4):
            for linha in range(4):
                int_stream.append(bloco[linha][coluna])

    return bytes(int_stream)

