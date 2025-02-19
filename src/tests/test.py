import sys
import socket
import threading
import numpy as np
import matplotlib.pyplot as plt
from PyQt5.QtWidgets import QApplication, QWidget, QLabel, QLineEdit, QPushButton, QVBoxLayout, QMessageBox

# Conversão de Dados
class Converter:
    @staticmethod
    def text_to_binary(text):
        return ''.join(format(ord(char), '08b') for char in text)

    @staticmethod
    def binary_to_text(binary):
        return ''.join(chr(int(binary[i:i+8], 2)) for i in range(0, len(binary), 8))

# Codificação PAM5
class PAM5Coder:
    pam5_mapping = {
        '0000': -2, '0001': -1, '0010': 0, '0011': 1, '0100': 2,
        '0101': -1.5, '0110': -0.5, '0111': 0.5, '1000': 1.5, '1001': 2.5,
        '1010': -1.25, '1011': -0.75, '1100': 0.25, '1101': 0.75, '1110': 1.25, '1111': 1.75
    }
    
    reverse_map = {v: k for k, v in pam5_mapping.items()}

    @classmethod
    def bin_to_pam5(cls, binary):
        chunks = [binary[i:i + 4] for i in range(0, len(binary), 4)]
        return [cls.pam5_mapping[chunk] for chunk in chunks]

    @classmethod
    def pam5_to_bin(cls, symbols):
        return ''.join(cls.reverse_map[s] for s in symbols)

# Gráfico da Onda PAM5
class PAM5Graph:
    @staticmethod
    def plot(symbols):
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

# Servidor
class PAM5Server:
    def __init__(self, host="0.0.0.0", port=5050):
        self.host = host
        self.port = port

    def start(self):
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

# Cliente
class PAM5Client:
    def __init__(self, host="127.0.0.1", port=5050):
        self.host = host
        self.port = port

    def send(self, message):
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((self.host, self.port))

        binary_data = Converter.text_to_binary(message)
        pam5_symbols = PAM5Coder.bin_to_pam5(binary_data)
        pam5_string = ",".join(map(str, pam5_symbols))

        client_socket.sendall(pam5_string.encode())
        client_socket.close()

        print(f"Mensagem '{message}' enviada com sucesso!")

# Interface Gráfica com PyQt5
class PAM5Interface(QWidget):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("Comunicação PAM5")
        self.setGeometry(300, 300, 400, 300)

        self.message_label = QLabel("Digite sua mensagem:")
        self.message_entry = QLineEdit(self)
        self.send_button = QPushButton("Enviar Mensagem", self)
        self.receive_button = QPushButton("Receber Mensagem", self)
        self.graph_button = QPushButton("Visualizar Gráfico", self)
        self.text_output = QLabel("", self)

        self.send_button.clicked.connect(self.send_message)
        self.receive_button.clicked.connect(self.receive_message)
        self.graph_button.clicked.connect(self.show_graph)

        layout = QVBoxLayout()
        layout.addWidget(self.message_label)
        layout.addWidget(self.message_entry)
        layout.addWidget(self.send_button)
        layout.addWidget(self.receive_button)
        layout.addWidget(self.graph_button)
        layout.addWidget(self.text_output)

        self.setLayout(layout)

    def send_message(self):
        message = self.message_entry.text()
        if message:
            client = PAM5Client()
            client.send(message)
            self.text_output.setText(f"Mensagem enviada: {message}")
        else:
            QMessageBox.warning(self, "Aviso", "Por favor, insira uma mensagem!")

    def receive_message(self):
        server = PAM5Server()
        server_thread = threading.Thread(target=server.start, daemon=True)
        server_thread.start()

    def show_graph(self):
        # Para fins de exemplo, usaremos um gráfico gerado a partir de uma mensagem fictícia
        symbols = [2, 1.75, 0, -2, 0.5, -2, 1.25, 2.5]  # Exemplo de símbolos PAM5
        PAM5Graph.plot(symbols)

# Função principal
if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = PAM5Interface()
    window.show()
    sys.exit(app.exec_())
