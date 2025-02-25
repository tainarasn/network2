import tkinter as tk
from tkinter import messagebox, scrolledtext
import threading
import socket
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import numpy as np
import base64 

class PAM5Server:
    # função elaborada pela equipe
    def __init__(self, host="0.0.0.0", port=5050, gui_callback=None):
        self.host = host
        self.port = port
        self.gui_callback = gui_callback
        
        # Flag para ativar/desativar descriptografia
        self.use_decryption = True  # Por padrão, a descriptografia está ativada

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

        self.reverse_map = {tuple(v): k for k, v in self.pam5_4d_mapping.items()}

    # função adaptada pela equipe da origem: https://www.reddit.com/r/learnpython/comments/jb7f6b/vigenere_cipher_implementation/?tl=pt-br&rdt=54879
    def vigenere_decrypt(self, encrypted_message, key):
        decrypted_message = b""
        key_length = len(key)
        key_bytes = key.encode('latin-1')
        for i in range(len(encrypted_message)):
            char = encrypted_message[i].encode('latin-1')
            key_char = key_bytes[i % key_length]
            decrypted_char = bytes([(char[0] - key_char) % 256])
            decrypted_message += decrypted_char
        return decrypted_message.decode('latin-1')


    # função elaborada pela equipe com a biblioteca Tkinter e Base64
    def start(self):
        try:
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.bind((self.host, self.port))
            server_socket.listen(1)
            print(f"Servidor aguardando conexão na porta {self.port}...")

            while True:
                conn, addr = server_socket.accept()
                print(f"Conexão estabelecida com {addr}")

                try:
                    data = []
                    while True:
                        chunk = conn.recv(4096).decode('latin-1')
                        if not chunk:
                            break
                        data.append(chunk)

                    pam5_signal = ''.join(data)
                    self.pam5_signal = pam5_signal

                    print(f"Sinal 4D-PAM5 recebido: {pam5_signal}")
                    print(f"Tamanho do sinal 4D-PAM5 recebido: {len(pam5_signal.split(','))}")

                    if self.use_decryption:
                        # decodifica 4D-PAM5 para binário
                        binary_message = self.pam5_4d_to_binary(pam5_signal)

                        # converte binário para texto (mensagem criptografada em Base64)
                        encrypted_message_base64 = self.binary_to_bytes(binary_message)
                        print(f"Mensagem criptografada (Base64): {encrypted_message_base64}")

                        # adiciona padding à string Base64, se necessário
                        padding = len(encrypted_message_base64) % 4
                        if padding:
                            encrypted_message_base64 += '=' * (4 - padding)

                        # decodifica a mensagem criptografada de Base64
                        try:
                            print(f"Mensagem criptografada (Base64 recebida): {encrypted_message_base64}")
                            encrypted_message = base64.b64decode(encrypted_message_base64.encode('latin-1'))
                            print(f"Mensagem criptografada (bytes decodificados): {encrypted_message}")
                        except Exception as e:
                            print(f"Erro ao decodificar Base64: {e}")
                            raise ValueError("String Base64 inválida")

                        # descriptografa a mensagem criptografada usando a Cifra de Vigenère
                        key = "aB3$fG7!kL9@mN1#pQ5"  # chave
                        decrypted_message = self.vigenere_decrypt(encrypted_message.decode('latin-1'), key)
                        print(f"Mensagem recebida: {decrypted_message}")
                    else:
                        # se a descriptografia estiver desativada, decodificar o sinal 4D-PAM5 diretamente para texto
                        binary_message = self.pam5_4d_to_binary(pam5_signal)
                        decrypted_message = self.binary_to_bytes(binary_message)
                        print(f"Mensagem recebida (sem descriptografia): {decrypted_message}")

                    # atualiza a interface gráfica com a mensagem original
                    if self.gui_callback:
                        if self.use_decryption:
                            self.gui_callback(decrypted_message, self.pam5_signal,encrypted_message_base64)
                        else:
                            self.gui_callback(decrypted_message, self.pam5_signal)
                                
                except Exception as e:
                    print(f"Erro ao processar mensagem: {e}")
                finally:
                    conn.close()
        except Exception as e:
            print(f"Erro no servidor: {e}")

    # função elaborada pela equipe
    def pam5_4d_to_binary(self, pam5_signal):
        if not pam5_signal:
            raise ValueError("Sinal 4D-PAM5 recebido está vazio")
    
        # verifica se o sinal contém apenas números e vírgulas
        if not all(c.isdigit() or c == ',' or c == '-' for c in pam5_signal):
            raise ValueError("Sinal 4D-PAM5 contém caracteres inválidos")
        
        try:
            symbols = [int(s) for s in pam5_signal.split(',') if s.strip()]
        except ValueError as e:
            raise ValueError(f"Erro ao converter sinal 4D-PAM5 para float: {e}")

        print(f"Símbolos 4D-PAM5: {symbols}")
        print(f"Número de símbolos 4D-PAM5: {len(symbols)}")
        
        binary_message = ''
        for i in range(0, len(symbols), 4):
            vector = tuple(symbols[i:i+4])
            closest_value = min(self.reverse_map.keys(), key=lambda x: np.linalg.norm(np.array(x) - np.array(vector)))
            binary_message += self.reverse_map[closest_value]
        
        print(f"Mensagem em binário: {binary_message}")
        print(f"Tamanho da mensagem binária: {len(binary_message)} bits")
        return binary_message

    # função elaborada pela equipe
    def binary_to_bytes(self, binary_message):
        binary_message = binary_message.replace(" ", "")
        print(f"Binário para conversão: {binary_message}")
        # converte binário para texto usando ASCII estendido
        text = ''.join(chr(int(binary_message[i:i+8], 2)) for i in range(0, len(binary_message), 8))
        return text
            
class ServerInterface(tk.Tk):
     # função elaborada pela equipe com biblioteca Tkinter
    def __init__(self):
        super().__init__()
        self.title("Servidor 4D-PAM5")
        self.geometry("800x900")
        self.server = PAM5Server(gui_callback=self.update_received_message)
        
        self.label = tk.Label(self, text="Aguardando mensagens...")
        self.label.pack(pady=20)
        
        self.start_button = tk.Button(self, text="Iniciar Servidor", command=self.start_server)
        self.start_button.pack(pady=10)

        # botão para ativar/desativar descriptografia
        self.decryption_button = tk.Button(self, text="Desativar Descriptografia", command=self.toggle_decryption)
        self.decryption_button.pack(pady=10)

        self.text_area = scrolledtext.ScrolledText(self, wrap=tk.WORD, width=80, height=10)
        self.text_area.pack(pady=10)
        
        self.text_output = tk.Label(self, text="Sinais gerados pelo algoritmo 4D-Pam5", wraplength=350)
        self.text_output.pack(pady=10)

        self.fig, self.ax = plt.subplots(figsize=(6, 4))
        self.canvas = FigureCanvasTkAgg(self.fig, master=self)
        self.canvas.get_tk_widget().pack(pady=10)

    # função elaborada pela equipe
    def toggle_decryption(self):
        # alternar entre ativar e desativar a descriptografia
        self.server.use_decryption = not self.server.use_decryption
        if self.server.use_decryption:
            self.decryption_button.config(text="Desativar Descriptografia")
        else:
            self.decryption_button.config(text="Ativar Descriptografia")
        messagebox.showinfo("Descriptografia", f"Descriptografia {'ativada' if self.server.use_decryption else 'desativada'}")

    # função adaptada pela equipe de origem: https://pt.stackoverflow.com/questions/341038/como-fazer-threads-para-servidor-em-python
    def start_server(self):
        server_thread = threading.Thread(target=self.server.start, daemon=True)
        server_thread.start()
        messagebox.showinfo("Servidor", "Servidor iniciado e aguardando conexões!")

    # função elaborada pela equipe com a biblioteca Tkinter
    def update_received_message(self, message, pam5_signal,encrypted=''):
        self.text_output.config(text=f"Mensagem original: {message}")
        
        binary_message = ' '.join(format(ord(char), '08b') for char in message)
        self.text_area.tag_configure("bold", font=("TkDefaultFont", 10, "bold"))
        self.text_area.tag_configure("center", justify="center")
        self.text_area.insert(tk.END, "___________DESMONTANDO A CODIFICAÇÃO___________\n", "bold")
        self.text_area.tag_add("center", "end-2l", "end-1l")
        self.text_area.insert(tk.END, f"\nSinal 4D-PAM5 recebido: \n","bold")
        self.text_area.insert(tk.END, f"{pam5_signal}\n")
        self.text_area.insert(tk.END, f"\nSinal em Binário: \n","bold")
        self.text_area.insert(tk.END, f"{binary_message}\n")
        if encrypted != '':
            self.text_area.insert(tk.END, f"\nSinal criptogafado: \n","bold")
            self.text_area.insert(tk.END, f"{encrypted}\n")
        self.text_area.insert(tk.END, f"\nMENSAGEM ORIGINAL: ", "bold")
        self.text_area.insert(tk.END, f"{message if encrypted != '' else binary_message}\n")
        self.text_area.insert(tk.END, ".................................................\n", "bold")

        self.plot_pam5_signal(pam5_signal)

    # função elaborada pela equipe com a bilbioteca matplotlib
    def plot_pam5_signal(self, pam5_signal):
        symbols = [float(s) for s in pam5_signal.split(',')]
        self.ax.clear()
        
        
        x_vals = []
        y_vals = []

        for i in range(len(symbols)):
            x_vals.extend([i, i])
            y_vals.extend([symbols[i], symbols[i]])  

       
        y_vals[0] = 0
        y_vals[-1] = 0

        # Plota a onda quadrada
        self.ax.step(x_vals, y_vals, where='post', marker='o', linestyle='-', color='b')
        
        # Adiciona uma linha horizontal fraca no eixo Y = 0
        self.ax.axhline(y=0, color='gray', linestyle='--', linewidth=1, alpha=0.6)

        # Define os limites do eixo Y
        self.ax.set_ylim(-2, 2)

        # Define os ticks do eixo Y para espaçamento de 1 unidade
        self.ax.set_yticks([-5,-4,-3,-2, -1, 0, 1, 2,3,4,5])  

        # Adiciona rótulos ao gráfico
        self.ax.set_title("Sinal 4D-PAM5")
        self.ax.set_xlabel("Índice")
        self.ax.set_ylabel("Valor")

        # Atualiza o canvas para exibir a nova configuração
        self.canvas.draw()
        
if __name__ == "__main__":
    app = ServerInterface()
    app.mainloop()