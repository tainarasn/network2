import tkinter as tk
from tkinter import messagebox, scrolledtext
import threading
import socket
import base64
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import numpy as np

class RSAEncryption:
    def __init__(self):
        self.private_key, self.public_key = self.load_or_generate_keys()

    def load_or_generate_keys(self):
        try:
            with open("private.pem", "rb") as priv_file:
                private_key = serialization.load_pem_private_key(
                    priv_file.read(),
                    password=None
                )
            with open("public.pem", "rb") as pub_file:
                public_key = serialization.load_pem_public_key(pub_file.read())
        except (FileNotFoundError, ValueError):
            private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            public_key = private_key.public_key()

            with open("private.pem", "wb") as priv_file:
                priv_file.write(private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ))

            with open("public.pem", "wb") as pub_file:
                pub_file.write(public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ))

        return private_key, public_key

    def decrypt_message(self, encrypted_message):
        try:
            encrypted_bytes = base64.b64decode(encrypted_message)
            decrypted = self.private_key.decrypt(
                encrypted_bytes,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            return decrypted.decode()
        except Exception as e:
            print(f"Erro ao descriptografar a mensagem: {e}")
            raise ValueError("Falha na descriptografia")

class PAM5Server:
    def __init__(self, host="0.0.0.0", port=5050, rsa=None, gui_callback=None):
        self.host = host
        self.port = port
        self.rsa = rsa
        self.gui_callback = gui_callback

        # Mapeamento 4D-PAM5 para binário
        self.pam5_4d_mapping = {
            '0000': [-2, -2, -2, -2], '0001': [-2, -2, -2, -1], '0010': [-2, -2, -2, 0], '0011': [-2, -2, -2, 1], '0100': [-2, -2, -2, 2],
            '0101': [-2, -2, -1, -2], '0110': [-2, -2, -1, -1], '0111': [-2, -2, -1, 0], '1000': [-2, -2, -1, 1], '1001': [-2, -2, -1, 2],
            '1010': [-2, -2, 0, -2], '1011': [-2, -2, 0, -1], '1100': [-2, -2, 0, 0], '1101': [-2, -2, 0, 1], '1110': [-2, -2, 0, 2],
            '1111': [-2, -2, 1, -2]
            # Adicione mais mapeamentos conforme necessário
        }
        self.reverse_map = {tuple(v): k for k, v in self.pam5_4d_mapping.items()}

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
                    pam5_signal = conn.recv(4096).decode()
                    print(f"Sinal 4D-PAM5 recebido: {pam5_signal}")
                    print(f"Tamanho do sinal 4D-PAM5 recebido: {len(pam5_signal)}")

                    if pam5_signal == "GET_PUBLIC_KEY":
                        print("Enviando chave pública para o cliente...")
                        conn.sendall(self.rsa.public_key.public_bytes(
                            encoding=serialization.Encoding.PEM,
                            format=serialization.PublicFormat.SubjectPublicKeyInfo
                        ))
                        conn.close()
                        continue

                    # 1. Decodificar 4D-PAM5 para binário
                    binary_message = self.pam5_4d_to_binary(pam5_signal)
                    print(f"Mensagem em binário: {binary_message}")

                    # 2. Converter binário para bytes (mensagem criptografada)
                    encrypted_message = self.binary_to_bytes(binary_message)
                    print(f"Mensagem criptografada: {encrypted_message}")
                    print(f"Tamanho da mensagem criptografada: {len(encrypted_message)}")

                    # 3. Verificar o tamanho da mensagem criptografada
                    if len(encrypted_message) != 256:  # Tamanho esperado para uma chave RSA de 2048 bits
                        raise ValueError("Tamanho da mensagem criptografada incorreto")

                    # 4. Descriptografar a mensagem criptografada usando a chave privada RSA
                    decrypted_message = self.rsa.decrypt_message(base64.b64encode(encrypted_message).decode())
                    print(f"Mensagem recebida: {decrypted_message}")

                    # 5. Atualizar a interface gráfica com a mensagem original
                    if self.gui_callback:
                        self.gui_callback(decrypted_message)
                        
                except Exception as e:
                    print(f"Erro ao processar mensagem: {e}")
                finally:
                    conn.close()
        except Exception as e:
            print(f"Erro no servidor: {e}")

    def pam5_4d_to_binary(self, pam5_signal):
        symbols = [float(s) for s in pam5_signal.split(',')]
        print(f"Símbolos 4D-PAM5: {symbols}")
        print(f"Número de símbolos 4D-PAM5: {len(symbols)}")
        
        if len(symbols) % 4 != 0:
            raise ValueError(f"Número incorreto de símbolos 4D-PAM5: {len(symbols)} (deve ser múltiplo de 4)")
        
        binary_message = ''
        for i in range(0, len(symbols), 4):
            vector = tuple(symbols[i:i+4])
            closest_value = min(self.reverse_map.keys(), key=lambda x: np.linalg.norm(np.array(x) - np.array(vector)))
            binary_message += self.reverse_map[closest_value]
            print(f"Vetor 4D-PAM5: {vector} -> Binário: {self.reverse_map[closest_value]}")
        
        print(f"Mensagem em binário: {binary_message}")
        print(f"Tamanho da mensagem binária: {len(binary_message)} bits")
        return binary_message

    def binary_to_bytes(self, binary_message):
        binary_message = binary_message.replace(" ", "")
        print(f"Binário para conversão: {binary_message}")
        if len(binary_message) != 2048:
            raise ValueError(f"Tamanho do binário incorreto: {len(binary_message)} bits")
        return bytes(int(binary_message[i:i+8], 2) for i in range(0, len(binary_message), 8))
    
class ServerInterface(tk.Tk):
        def __init__(self):
            super().__init__()
            self.title("Servidor 4D-PAM5")
            self.geometry("700x700")
            self.rsa = RSAEncryption()
            self.server = PAM5Server(gui_callback=self.update_received_message, rsa=self.rsa)
            
            self.label = tk.Label(self, text="Aguardando mensagens...")
            self.label.pack(pady=20)
            
            self.start_button = tk.Button(self, text="Iniciar Servidor", command=self.start_server)
            self.start_button.pack(pady=10)

            self.text_area = scrolledtext.ScrolledText(self, wrap=tk.WORD, width=80, height=10)
            self.text_area.pack(pady=10)
            
            self.text_output = tk.Label(self, text="Sinais gerados pelo algoritmo 4D-Pam5", wraplength=350)
            self.text_output.pack(pady=10)

            self.fig, self.ax = plt.subplots(figsize=(6, 4))
            self.canvas = FigureCanvasTkAgg(self.fig, master=self)
            self.canvas.get_tk_widget().pack(pady=10)

        def start_server(self):
            server_thread = threading.Thread(target=self.server.start, daemon=True)
            server_thread.start()
            messagebox.showinfo("Servidor", "Servidor iniciado e aguardando conexões!")

        def update_received_message(self, message):
            self.text_output.config(text=f"Mensagem original: {message}")
            
            encrypted_message = base64.b64encode(message.encode()).decode()
            binary_message = ' '.join(format(ord(char), '08b') for char in message)
            
            self.text_area.insert(tk.END, f"Mensagem recebida: {message}\n")
            self.text_area.insert(tk.END, f"Binário convertido para texto criptografado: {encrypted_message}\n")
            self.text_area.insert(tk.END, f"Sinal decodificado em Binário: {binary_message}\n")

            self.plot_pam5_signal(message)

        def plot_pam5_signal(self, message):
            symbols = [ord(char) % 5 - 2 for char in message]
            self.ax.clear()
            self.ax.plot(symbols, marker='o')
            self.ax.set_title("Sinal 4D-PAM5")
            self.ax.set_xlabel("Índice")
            self.ax.set_ylabel("Valor")
            self.canvas.draw()
        
if __name__ == "__main__":
    app = ServerInterface()
    app.mainloop()