import tkinter as tk
from tkinter import messagebox
import threading
import numpy as np
import matplotlib.pyplot as plt
import socket

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
        # Arredonda os símbolos para garantir precisão no mapeamento
        symbols = [round(s, 2) for s in symbols]
        return ''.join(cls.reverse_map[s] for s in symbols)


# Gráfico da Onda PAM5
class PAM5Graph:
    @staticmethod
    def plot(symbols):
        t = np.arange(len(symbols))  # Tempo discreto (um tempo para cada símbolo)
        
        # Melhoria no gráfico para uma linha contínua
        plt.figure(figsize=(10, 4))
        plt.plot(t, symbols, linestyle='-', marker='o', color='b', label='Sinal PAM5')

        plt.xlabel("Tempo (símbolos)")
        plt.ylabel("Nível de Amplitude")
        plt.title("Forma de Onda 4D-PAM5")
        plt.yticks(sorted(set(symbols)))  # Apenas níveis utilizados
        plt.grid()
        plt.legend()
        plt.show()
# Servidor
class PAM5Server:
    def __init__(self, host="0.0.0.0", port=5050, gui_callback=None):
        self.host = host
        self.port = port
        self.gui_callback = gui_callback  # Função para atualizar a GUI do cliente

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

        # Gerar a versão binária
        binario_msg = Converter.text_to_binary(mensagem_recuperada)
        
        # Gerar a versão criptografada
        encrypted_msg = self.apply_encryption(mensagem_recuperada)

        # Atualiza a GUI com a mensagem recebida e as outras informações
        if self.gui_callback:
            self.gui_callback(mensagem_recuperada, binario_msg, encrypted_msg)

        conn.close()

    def apply_encryption(self, message):
        # Aqui você pode aplicar outro tipo de criptografia, como cifra de César ou outro
        shift = 3  # exemplo de chave de deslocamento
        return ''.join(chr((ord(c) + shift - 32) % 95 + 32) for c in message)


# Cliente
class PAM5Client:
    def __init__(self, host="127.0.0.1", port=5050):
        self.host = host
        self.port = port

    def send(self, message):
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((self.host, self.port))

        # Criptografando a mensagem antes de qualquer conversão
        encrypted_message = self.apply_encryption(message)

        # Convertendo a mensagem criptografada para binário
        binary_data = Converter.text_to_binary(encrypted_message)

        # Codificando a mensagem binária para PAM5
        pam5_symbols = PAM5Coder.bin_to_pam5(binary_data)
        pam5_string = ",".join(map(str, pam5_symbols))

        client_socket.sendall(pam5_string.encode())
        client_socket.close()

        print(f"Mensagem '{message}' enviada com sucesso!")

    def apply_encryption(self, message):
        # Exemplo simples de criptografia
        shift = 3  # Exemplo de cifra de César
        return ''.join(chr((ord(c) + shift - 32) % 95 + 32) for c in message)

# Interface Gráfica com Tkinter
class PAM5Interface(tk.Tk):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        
        self.title("Comunicação PAM5")
        self.geometry("500x500")

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

        self.encrypted_msg_label = tk.Label(self, text="Mensagem Criptografada: ")
        self.encrypted_msg_label.pack(pady=10)

        self.binary_msg_label = tk.Label(self, text="Mensagem em Binário: ")
        self.binary_msg_label.pack(pady=10)

        self.transformed_msg_label = tk.Label(self, text="Mensagem após Algoritmo: ")
        self.transformed_msg_label.pack(pady=10)

        self.graph_button = tk.Button(self, text="Visualizar Gráfico", command=self.show_graph)
        self.graph_button.pack(pady=10)

        self.server = PAM5Server(gui_callback=self.update_received_message)

    def send_message(self):
        message = self.message_entry.get()
        if message:
            client = PAM5Client()
            
            # Exibindo a mensagem original
            self.text_output.config(text=f"Mensagem enviada: {message}")
            
            # Convertendo para binário
            binary_message = Converter.text_to_binary(message)
            self.binary_msg_label.config(text=f"Mensagem em Binário: {binary_message}")
            
            # Aplicando a criptografia (simulação, caso tenha algum algoritmo específico)
            encrypted_message = self.apply_encryption(message)
            self.encrypted_msg_label.config(text=f"Mensagem Criptografada: {encrypted_message}")
            
            # Aplicando o algoritmo de codificação PAM5
            client.send(message)
            
            # Convertendo a mensagem binária para PAM5
            pam5_message = ','.join(map(str, PAM5Coder.bin_to_pam5(binary_message)))
            self.transformed_msg_label.config(text=f"Mensagem após Algoritmo (PAM5): {pam5_message}")
            
        else:
            messagebox.showwarning("Aviso", "Por favor, insira uma mensagem!")
    def apply_encryption(self, message):
        # Implementar o algoritmo de criptografia aqui (exemplo simples de substituição)
        return ''.join(chr(ord(c) + 1) for c in message)  # Exemplo simples de criptografia

    def receive_message(self):
        # Cria e inicia o servidor em um thread separado
        server_thread = threading.Thread(target=self.server.start, daemon=True)
        server_thread.start()

    def update_received_message(self, message, bin_msg, encrypted_msg):
        """Atualiza a interface com a mensagem recebida pelo servidor e outras informações."""
        self.text_output.config(text=f"Mensagem recebida: {message}")
        self.binary_msg_label.config(text=f"Mensagem em Binário: {bin_msg}")
        self.encrypted_msg_label.config(text=f"Mensagem Criptografada: {encrypted_msg}")

        # Aplicando o algoritmo PAM5 na mensagem recebida e atualizando a interface
        pam5_message = ','.join(map(str, PAM5Coder.bin_to_pam5(bin_msg)))
        self.transformed_msg_label.config(text=f"Mensagem após Algoritmo (PAM5): {pam5_message}")


    def show_graph(self):
        # Para fins de exemplo, usaremos um gráfico gerado a partir de uma mensagem fictícia
        symbols = [2, 1.75, 0, -2, 0.5, -2, 1.25, 2.5]  # Exemplo de símbolos PAM5
        PAM5Graph.plot(symbols)

# Exemplo de execução do servidor e cliente
if __name__ == "__main__":
    app = PAM5Interface()
    app.mainloop()
