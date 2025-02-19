import tkinter as tk
from tkinter import messagebox, scrolledtext
import socket
import base64
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import numpy as np

class ClientInterface(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Cliente 4D-PAM5")
        self.geometry("800x900")
        
        # Elementos da interface gráfica
        self.label = tk.Label(self, text="Envie uma mensagem:")
        self.label.pack(pady=20)
        
        self.entry = tk.Entry(self, width=50)
        self.entry.pack(pady=10)
        
        self.send_button = tk.Button(self, text="Enviar", command=self.send_message)
        self.send_button.pack(pady=10)

        # Caixa de texto rolável para exibir valores
        self.text_area = scrolledtext.ScrolledText(self, wrap=tk.WORD, width=80, height=10)
        self.text_area.pack(pady=10)

        self.pam5_label = tk.Label(self, text="Sinal 4D-PAM5 enviado:")
        self.pam5_label.pack(pady=5)

        # Gráfico de sinais 4D-PAM5
        self.fig, self.ax = plt.subplots(figsize=(6, 4))
        self.canvas = FigureCanvasTkAgg(self.fig, master=self)
        self.canvas.get_tk_widget().pack(pady=10)

        # Mapeamento 4D-PAM5 para binário
        self.pam5_4d_mapping = {
            '0000': [-2, -2, -2, -2], '0001': [-2, -2, -2, -1], '0010': [-2, -2, -2, 0], '0011': [-2, -2, -2, 1], '0100': [-2, -2, -2, 2],
            '0101': [-2, -2, -1, -2], '0110': [-2, -2, -1, -1], '0111': [-2, -2, -1, 0], '1000': [-2, -2, -1, 1], '1001': [-2, -2, -1, 2],
            '1010': [-2, -2, 0, -2], '1011': [-2, -2, 0, -1], '1100': [-2, -2, 0, 0], '1101': [-2, -2, 0, 1], '1110': [-2, -2, 0, 2],
            '1111': [-2, -2, 1, -2]
            # Adicione mais mapeamentos conforme necessário
        }

    def send_message(self):
        message = self.entry.get()
        if message:
            try:
                # 1. Criptografar a mensagem com a chave pública do servidor
                self.text_area.tag_configure("bold", font=("TkDefaultFont", 10, "bold"))
                self.text_area.tag_configure("center", justify="center")
                self.text_area.insert(tk.END, "___________MONTANDO A CODIFICAÇÃO___________\n", "bold")
                self.text_area.tag_add("center", "end-2l", "end-1l")
                #self.text_area.insert(tk.END, f"Mensagem Original: {base64.b64encode(message).decode()}\n")
                
                self.text_area.insert(tk.END, "\nMENSAGEM ORIGINAL: ","bold")
                self.text_area.insert(tk.END, f"{message}\n")
                
                encrypted_message = self.encrypt_message(message)
                self.text_area.insert(tk.END, "\nMensagem criptografada:\n","bold")
                self.text_area.insert(tk.END, f"{base64.b64encode(encrypted_message).decode()}\n")

                # 2. Converter a mensagem criptografada para binário
                binary_message = self.message_to_binary(encrypted_message)
                self.text_area.insert(tk.END, f"\nMensagem em binário:", "bold")
                self.text_area.insert(tk.END, f" {binary_message}\n")

                # 3. Codificar o binário em sinal 4D-PAM5
                pam5_signal = self.binary_to_pam5(binary_message)
                self.text_area.insert(tk.END, f"\nSinal 4D-PAM5 da mensagem:\n","bold")
                self.text_area.insert(tk.END, f"{pam5_signal}\n")
                
                print(f"Tamanho do sinal 4D-PAM5 recebido: {len(pam5_signal.split(','))} (esperado: 2048)")

                # 4. Enviar o sinal 4D-PAM5 para o servidor
                self.send_to_server(pam5_signal)

                # 5. Plotar o gráfico de sinais 4D-PAM5
                self.plot_pam5_signal(pam5_signal)
            except Exception as e:
                messagebox.showerror("Erro", f"Erro ao processar mensagem: {e}")

    def plot_pam5_signal(self, pam5_signal):
        symbols = [float(s) for s in pam5_signal.split(',')]
        self.ax.clear()
        self.ax.plot(symbols, marker='o')
        self.ax.set_title("Sinal 4D-PAM5")
        self.ax.set_xlabel("Índice")
        self.ax.set_ylabel("Valor")
        self.canvas.draw()

    def encrypt_message(self, message):
        with open("public.pem", "rb") as pub_file:
            public_key = serialization.load_pem_public_key(pub_file.read())
        
        # Criptografar a mensagem usando a chave pública
        encrypted = public_key.encrypt(
            message.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        print(f"Mensagem criptografada: {encrypted}")
        print(f"Tamanho da mensagem criptografada: {len(encrypted)} bytes")
        
        # Verificar se o tamanho está correto
        if len(encrypted) != 256:
            raise ValueError(f"Tamanho da mensagem criptografada incorreto: {len(encrypted)} bytes (esperado: 256)")
        
        return encrypted

    def message_to_binary(self, message):
        # Converter bytes para binário
        binary_message = ''.join(format(byte, '08b') for byte in message)
        print(f"Binário gerado: {binary_message}")
        print(f"Tamanho do binário: {len(binary_message)} bits")
        print(f"Tamanho do binário gerado: {len(binary_message)} bits (esperado: 2048)")
        
        # Verificar se o tamanho está correto
        if len(binary_message) != 2048:
            raise ValueError(f"Tamanho do binário incorreto: {len(binary_message)} bits (esperado: 2048)")
        
        return binary_message

    def binary_to_pam5(self, binary_message):
        # Dividir o binário em grupos de 4 bits
        binary_groups = [binary_message[i:i+4] for i in range(0, len(binary_message), 4)]
        print(f"Grupos de 4 bits gerados: {len(binary_groups)} (esperado: 512)")
       

        print(f"Grupos de 4 bits: {binary_groups}")
        print(f"Número de grupos de 4 bits: {len(binary_groups)}")
        
        # Verificar se o número de grupos está correto
        if len(binary_groups) != 512:
            raise ValueError(f"Número incorreto de grupos de 4 bits: {len(binary_groups)} (esperado: 512)")
        
        # Mapear cada grupo de 4 bits para 4D-PAM5
        pam5_signal = []
        for group in binary_groups:
            if group in self.pam5_4d_mapping:
                pam5_signal.extend(self.pam5_4d_mapping[group])
            else:
                pam5_signal.extend([0, 0, 0, 0])  # Valor padrão se o grupo não for encontrado
        
        return ','.join(map(str, pam5_signal)).strip(',')

    def send_to_server(self, pam5_signal):
        try:
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.connect(("192.168.15.2", 5050))
            client_socket.sendall(pam5_signal.encode())  # Certifique-se de que pam5_signal está no formato correto
            print(f"Sinal 4D-PAM5 enviado: {pam5_signal}")
            client_socket.close()
            messagebox.showinfo("Sucesso", "Mensagem enviada com sucesso!")
        except Exception as e:
            messagebox.showerror("Erro", f"Erro ao enviar mensagem: {e}")

if __name__ == "__main__":
    app = ClientInterface()
    app.mainloop()