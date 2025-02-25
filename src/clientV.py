import tkinter as tk
from tkinter import messagebox, scrolledtext
import socket
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import numpy as np
import base64 

class ClientInterface(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Cliente 4D-PAM5")
        self.geometry("800x900")
        
        # Flag para ativar/desativar criptografia
        self.use_encryption = True  # Por padrão, a criptografia está ativada

        # Elementos da interface gráfica
        self.label = tk.Label(self, text="Envie uma mensagem:")
        self.label.pack(pady=20)
        
        self.entry = tk.Entry(self, width=50)
        self.entry.pack(pady=10)
        
        self.send_button = tk.Button(self, text="Enviar", command=self.send_message)
        self.send_button.pack(pady=10)

        # Botão para ativar/desativar criptografia
        self.encryption_button = tk.Button(self, text="Desativar Criptografia", command=self.toggle_encryption)
        self.encryption_button.pack(pady=10)

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
            '0000': [-2, -2, -2, -2],  
            '0001': [-2, -2, 1, 1],  
            '0010': [-2, -1, -1,  0],  
            '0011': [-1, -1,  0,  0],  
            '0100': [-1,  0,  0,  1],  
            '0101': [ 0,  0,  1,  1],  
            '0110': [ 0,  1,  1,  2],  
            '0111': [ 1,  1,  2,  2],  
            '1000': [ 1,  2,  2,  1],   
            '1001': [ 2,  2,  2,  1],  
            '1010': [-2, -1,  0,  1],  
            '1011': [-1,  0,  1,  2],  
            '1100': [ 0,  1,  2,  2],  
            '1101': [ 1,  2,  2,  2],  
            '1110': [ 2,  2,-1,-1],  
            '1111': [ 2,  2,  2,  2]  
        }

    def toggle_encryption(self):
        # Alternar entre ativar e desativar a criptografia
        self.use_encryption = not self.use_encryption
        if self.use_encryption:
            self.encryption_button.config(text="Desativar Criptografia")
        else:
            self.encryption_button.config(text="Ativar Criptografia")
        messagebox.showinfo("Criptografia", f"Criptografia {'ativada' if self.use_encryption else 'desativada'}")

 
    def vigenere_encrypt(self, message, key):
        encrypted_message = b""
        key_length = len(key)
        key_bytes = key.encode('latin-1')
        for i in range(len(message)):
            char = message[i].encode('latin-1')
            key_char = key_bytes[i % key_length]
            encrypted_char = bytes([(char[0] + key_char) % 256])
            encrypted_message += encrypted_char
        return encrypted_message
    

    def send_message(self):
        message = self.entry.get()
        if message:
            try:
                if self.use_encryption:
                    # criptografar a mensagem com a Cifra de Vigenère
                    key = "aB3$fG7!kL9@mN1#pQ5"  # chave
                    encrypted_message = self.vigenere_encrypt(message, key)
                    
                    # codifica a mensagem criptografada em Base64
                    encrypted_message_base64 = base64.b64encode(encrypted_message).decode('latin-1')
                    
                    # adiciona padding à string Base64, se necessário
                    padding = len(encrypted_message_base64) % 4
                    if padding:
                        encrypted_message_base64 += '=' * (4 - padding)
                    
                    self.text_area.tag_configure("bold", font=("TkDefaultFont", 10, "bold"))
                    self.text_area.tag_configure("center", justify="center")
                    self.text_area.insert(tk.END, "___________MONTANDO A CODIFICAÇÃO___________\n", "bold")
                    self.text_area.tag_add("center", "end-2l", "end-1l")
                    
                    self.text_area.insert(tk.END, "\nMENSAGEM ORIGINAL: ","bold")
                    self.text_area.insert(tk.END, f"{message}\n")
                    
                    self.text_area.insert(tk.END, "\nMensagem criptografada (Base64):\n","bold")
                    self.text_area.insert(tk.END, f"{encrypted_message_base64}\n")

                    # converte a mensagem criptografada (Base64) para binário
                    binary_message = self.message_to_binary(encrypted_message_base64)
                    self.text_area.insert(tk.END, f"\nMensagem em binário:", "bold")
                    self.text_area.insert(tk.END, f" {binary_message}\n")

                    # codifica o binário em sinal 4D-PAM5
                    pam5_signal = self.binary_to_pam5(binary_message)
                    self.text_area.insert(tk.END, f"\nSinal 4D-PAM5 da mensagem:\n","bold")
                    self.text_area.insert(tk.END, f"{pam5_signal}\n")
                    
                    print(f"Tamanho do sinal 4D-PAM5 enviado: {len(pam5_signal.split(','))}")
                    self.plot_pam5_signal(pam5_signal)

                    # enviar o sinal 4D-PAM5 para o servidor
                    self.send_to_server(pam5_signal)
                    
                    print(f"Mensagem criptografada (bytes): {encrypted_message}")
                    print(f"Mensagem criptografada (Base64): {encrypted_message_base64}")
                else:
                    # se a criptografia estiver desativada, converter a mensagem diretamente para 4D-PAM5
                    binary_message = self.message_to_binary(message)
                    pam5_signal = self.binary_to_pam5(message)
                    self.text_area.insert(tk.END, "\nMensagem enviada sem criptografia:\n","bold")
                    self.text_area.insert(tk.END, f"{message}\n")
                    self.text_area.insert(tk.END, f"\nSinal 4D-PAM5 da mensagem:\n","bold")
                    self.text_area.insert(tk.END, f"{pam5_signal}\n")
                    
                    print(f"Tamanho do sinal 4D-PAM5 enviado: {len(pam5_signal.split(','))}")
                    self.plot_pam5_signal(pam5_signal)

                    # envia o sinal 4D-PAM5 para o servidor
                    self.send_to_server(pam5_signal)

            except Exception as e:
                messagebox.showerror("Erro", f"Erro ao processar mensagem: {e}")

    def plot_pam5_signal(self, pam5_signal):
        symbols = [float(s) for s in pam5_signal.split(',')]
        self.ax.clear()
        
        # Lista para os eixos X e Y com transições quadradas
        x_vals = []
        y_vals = []

        for i in range(len(symbols)):
            x_vals.extend([i, i])  # Mantém cada ponto no mesmo índice X duas vezes
            y_vals.extend([symbols[i], symbols[i]])  # Repete o valor Y para criar um platô

        # força o primeiro e o último ponto a serem 0
        y_vals[0] = 0
        y_vals[-1] = 0

        # plota a onda quadrada
        self.ax.step(x_vals, y_vals, where='post', marker='o', linestyle='-', color='b')
        
        # adiciona uma linha horizontal fraca no eixo Y = 0
        self.ax.axhline(y=0, color='gray', linestyle='--', linewidth=1, alpha=0.6)

        # define os limites do eixo Y
        self.ax.set_ylim(-2, 2)

        # define os ticks do eixo Y para espaçamento de 1 unidade
        self.ax.set_yticks([-5,-4,-3,-2, -1, 0, 1, 2,3,4,5])  

        # adiciona rótulos ao gráfico
        self.ax.set_title("Sinal 4D-PAM5")
        self.ax.set_xlabel("Índice")
        self.ax.set_ylabel("Valor")

        # atualiza o canvas para exibir a nova configuração
        self.canvas.draw()

    # função 
    def message_to_binary(self, message):
        # converte mensagem para binário
        binary_message = ''.join(format(ord(char), '08b') for char in message)
        print(f"Binário gerado: {binary_message}")
        print(f"Tamanho do binário: {len(binary_message)} bits")
        
        return binary_message

    def binary_to_pam5(self, binary_message):
        # divide o binário em grupos de 4 bits
        binary_groups = [binary_message[i:i+4] for i in range(0, len(binary_message), 4)]
        print(f"Grupos de 4 bits gerados: {len(binary_groups)}")
    
        print(f"Grupos de 4 bits: {binary_groups}")
        
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
            client_socket.connect(("localhost", 5050))
            client_socket.sendall(pam5_signal.encode('latin-1'))  # Usar latin-1 para ASCII estendido
            print(f"Sinal 4D-PAM5 enviado: {pam5_signal}")
            client_socket.close()
            messagebox.showinfo("Sucesso", "Mensagem enviada com sucesso!")
        except Exception as e:
            messagebox.showerror("Erro", f"Erro ao enviar mensagem: {e}")

if __name__ == "__main__":
    app = ClientInterface()
    app.mainloop()