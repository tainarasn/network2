import numpy as np
import matplotlib.pyplot as plt
import socket
import threading
import tkinter as tk
from tkinter import messagebox

# Conversão de Dados
class Converter:
    @staticmethod
    def text_to_binary(text):
        """Converte um texto para binário usando ASCII estendido."""
        return ''.join(format(ord(char), '08b') for char in text)

    @staticmethod
    def binary_to_text(binary):
        """Converte um binário de volta para texto usando ASCII estendido."""
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
        """Converte uma sequência binária para símbolos 4D-PAM5."""
        chunks = [binary[i:i + 4] for i in range(0, len(binary), 4)]
        return [cls.pam5_mapping[chunk] for chunk in chunks]

    @classmethod
    def pam5_to_bin(cls, symbols):
        """Converte símbolos 4D-PAM5 de volta para binário."""
        return ''.join(cls.reverse_map[s] for s in symbols)

# Gráfico da Onda PAM5
class PAM5Graph:
    @staticmethod
    def plot(symbols):
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

# Cliente
class PAM5Client:
    def __init__(self, host="127.0.0.1", port=5050):
        self.host = host
        self.port = port

    def send(self, message):
        """Envia uma mensagem para o servidor."""
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((self.host, self.port))

        # Conversão Texto → Binário → PAM5
        binary_data = Converter.text_to_binary(message)
        pam5_symbols = PAM5Coder.bin_to_pam5(binary_data)
        pam5_string = ",".join(map(str, pam5_symbols))

        # Enviar os dados
        client_socket.sendall(pam5_string.encode())

        client_socket.close()
        print(f"Mensagem '{message}' enviada com sucesso!")




# Conversão de Dados
class Converter:
    @staticmethod
    def text_to_binary(text):
        """Converte um texto para binário usando ASCII estendido."""
        return ''.join(format(ord(char), '08b') for char in text)

    @staticmethod
    def binary_to_text(binary):
        """Converte um binário de volta para texto usando ASCII estendido."""
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
        """Converte uma sequência binária para símbolos 4D-PAM5."""
        chunks = [binary[i:i + 4] for i in range(0, len(binary), 4)]
        return [cls.pam5_mapping[chunk] for chunk in chunks]

    @classmethod
    def pam5_to_bin(cls, symbols):
        """Converte símbolos 4D-PAM5 de volta para binário."""
        return ''.join(cls.reverse_map[s] for s in symbols)

# Gráfico da Onda PAM5
class PAM5Graph:
    @staticmethod
    def plot(symbols):
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

# Cliente
class PAM5Client:
    def __init__(self, host="127.0.0.1", port=5050):
        self.host = host
        self.port = port

    def send(self, message):
        """Envia uma mensagem para o servidor."""
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((self.host, self.port))

        # Conversão Texto → Binário → PAM5
        binary_data = Converter.text_to_binary(message)
        pam5_symbols = PAM5Coder.bin_to_pam5(binary_data)
        pam5_string = ",".join(map(str, pam5_symbols))

        # Enviar os dados
        client_socket.sendall(pam5_string.encode())

        client_socket.close()
        print(f"Mensagem '{message}' enviada com sucesso!")

# Interface Gráfica com Tkinter
class PAM5Interface(tk.Tk):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        
        self.title("Comunicação PAM5")
        self.geometry("400x400")

        self.message_label = tk.Label(self, text="Digite sua mensagem:")
        self.message_label.pack(pady=10)

        self.message_entry = tk.Entry(self, width=40)
        self.message_entry.pack(pady=10)

        self.send_button = tk.Button(self, text="Enviar Mensagem", command=self.send_message)
        self.send_button.pack(pady=10)

        self.receive_button = tk.Button(self, text="Receber Mensagem", command=self.receive_message)
        self.receive_button.pack(pady=10)

        self.text_output = tk.Label(self, text="", wraplength=300)
        self.text_output.pack(pady=10)

        self.graph_button = tk.Button(self, text="Visualizar Gráfico", command=self.show_graph)
        self.graph_button.pack(pady=10)

    def send_message(self):
        """Envia a mensagem digitada para o servidor."""
        message = self.message_entry.get()
        if message:
            client = PAM5Client()
            client.send(message)
            self.text_output.config(text=f"Mensagem enviada: {message}")
        else:
            messagebox.showwarning("Aviso", "Por favor, insira uma mensagem!")

    def receive_message(self):
        """Recebe a mensagem do servidor."""
        server = PAM5Server()
        server_thread = threading.Thread(target=server.start)
        server_thread.daemon = True
        server_thread.start()
        
    def show_graph(self):
        """Exibe o gráfico PAM5."""
        # Para fins de exemplo, usaremos um gráfico gerado a partir de uma mensagem fictícia
        symbols = [2, 1.75, 0, -2, 0.5, -2, 1.25, 2.5]  # Exemplo de símbolos PAM5
        PAM5Graph.plot(symbols)


# Exemplo de execução do servidor e cliente
if __name__ == "__main__":
    # Inicia a interface gráfica
    app = PAM5Interface()
    app.mainloop()

# if __name__ == "__main__":
#     # Inicia o servidor em um thread
#     server = PAM5Server()
#     server_thread = threading.Thread(target=server.start)
#     server_thread.start()

#     # # Cliente envia uma mensagem
#     # client = PAM5Client()
#     # client.send("Olá!")
    
    
    