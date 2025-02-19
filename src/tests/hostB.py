import socket

def start_server():
    host = "0.0.0.0"  # Aceita conexões de qualquer IP
    port = 12345       # Porta de comunicação

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
