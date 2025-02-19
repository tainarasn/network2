import numpy as np

# Mapeamento de 4 bits para valores PAM5
pam5_mapping = {
    '0000': -2, '0001': -1, '0010': 0, '0011': 1, '0100': 2,
    '0101': -2, '0110': -1, '0111': 0, '1000': 1, '1001': 2,
    '1010': -2, '1011': -1, '1100': 0, '1101': 1, '1110': 2, '1111': -2
}

def bin_to_pam5(binary):
    """Converte uma sequência binária para símbolos 4D-PAM5."""
    # Divide em blocos de 4 bits
    chunks = [binary[i:i + 4] for i in range(0, len(binary), 4)]
    # Mapeia cada bloco para os níveis PAM5
    pam5_symbols = [pam5_mapping[chunk] for chunk in chunks]
    return pam5_symbols

def pam5_to_bin(symbols):
    """Converte símbolos 4D-PAM5 de volta para binário."""
    # Inverte o dicionário para decodificar
    reverse_map = {v: k for k, v in pam5_mapping.items()}
    # Traduz cada símbolo de volta para binário
    binary = ''.join(reverse_map[s] for s in symbols)
    return binary

# Teste do 4D-PAM5
if __name__ == "__main__":
    mensagem = "Olá!"
    binario = text_to_binary(mensagem)

    print("Binário:", binario)

    pam5_codificado = bin_to_pam5(binario)
    print("Símbolos PAM5:", pam5_codificado)

    binario_recuperado = pam5_to_bin(pam5_codificado)
    mensagem_recuperada = binary_to_text(binario_recuperado)

    print("Mensagem decodificada:", mensagem_recuperada)
