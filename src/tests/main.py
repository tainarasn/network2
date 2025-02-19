import numpy as np
import matplotlib.pyplot as plt
import socket

#convert
def text_to_binary(text):
    """Converte um texto para binário usando ASCII estendido."""
    binary_data = ''.join(format(ord(char), '08b') for char in text)
    return binary_data

def binary_to_text(binary):
    """Converte um binário de volta para texto usando ASCII estendido."""
    text = ''.join(chr(int(binary[i:i+8], 2)) for i in range(0, len(binary), 8))
    return text

#algorithm
# Mapeamento de 4 bits para valores PAM5
pam5_mapping = {
    '0000': -2, '0001': -1, '0010': 0, '0011': 1, '0100': 2,
    '0101': -1.5, '0110': -0.5, '0111': 0.5, '1000': 1.5, '1001': 2.5,
    '1010': -1.25, '1011': -0.75, '1100': 0.25, '1101': 0.75, '1110': 1.25, '1111': 1.75
}
 
 
reverse_map = {v: k for k, v in pam5_mapping.items()}

def bin_to_pam5(binary):
    """Converte uma sequência binária para símbolos 4D-PAM5."""
    chunks = [binary[i:i + 4] for i in range(0, len(binary), 4)]
    pam5_symbols = [pam5_mapping[chunk] for chunk in chunks]
    return pam5_symbols

def pam5_to_bin(symbols):
    """Converte símbolos 4D-PAM5 de volta para binário."""
    binary = ''.join(reverse_map[s] for s in symbols)
    return binary


# graph

def plot_pam5_wave(symbols):
    """Gera um gráfico da forma de onda PAM5."""
    t = np.arange(len(symbols))  # Tempo discreto (um tempo para cada símbolo)
    
    plt.figure(figsize=(10, 4))
    plt.step(t, symbols, where='mid', linestyle='-', marker='o', color='b', label='Sinal PAM5')

    plt.xlabel("Tempo (símbolos)")
    plt.ylabel("Nível de Amplitude")
    plt.title("Forma de Onda 4D-PAM5")
    plt.yticks(sorted(set(symbols)))  # Apenas níveis utilizados
    plt.grid()
    plt.legend()
    plt.show()


#server 
def start_server():
    host = "0.0.0.0"  # Aceita conexões de qualquer IP
    port = 5050       # Porta de comunicação

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(1)
    print(f"Servidor aguardando conexão na porta {port}...")

    conn, addr = server_socket.accept()
    print(f"Conexão estabelecida com {addr}")

    # Receber os dados
    data = conn.recv(1024).decode()
    print("Dados recebidos:", data)

    # Decodificação PAM5 → Binário → Texto
    symbols = list(map(float, data.split(",")))
    binario_recuperado = pam5_to_bin(symbols)
    mensagem_recuperada = binary_to_text(binario_recuperado)

    print(f"Mensagem recuperada: {mensagem_recuperada}")

    conn.close()

start_server()





