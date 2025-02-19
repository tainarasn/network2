import socket
from classes import Converter
from classes.pam5coder import PAM5Coder
from classes.pam5graph import PAM5Graph

# Servidor
class PAM5Server:
    def __init__(self, host="0.0.0.0", port=5050):
        self.host = host
        self.port = port

    def start(self):
        """Inicia o servidor para receber mensagens."""
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind((self.host, self.port))
        server_socket.listen(1)
        print(f"Servidor aguardando conexão na porta {self.port}...")

        conn, addr = server_socket.accept()
        print(f"Conexão estabelecida com {addr}")

        # Receber os dados
        data = conn.recv(1024).decode()
        print("Dados recebidos:", data)

        # Decodificação PAM5 → Binário → Texto
        symbols = list(map(float, data.split(",")))
        binario_recuperado = PAM5Coder.pam5_to_bin(symbols)
        mensagem_recuperada = Converter.binary_to_text(binario_recuperado)

        print(f"Mensagem recuperada: {mensagem_recuperada}")

        conn.close()