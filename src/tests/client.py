import tkinter as tk
from tkinter import messagebox
import socket
import base64
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes


# ====================== CRIPTOGRAFIA RSA ======================

class RSAClient:
    def __init__(self, server_ip, server_port):
        self.server_ip = server_ip
        self.server_port = server_port
        self.public_key = self.get_server_public_key()

    def get_server_public_key(self):
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((self.server_ip, self.server_port))
        client_socket.sendall("GET_PUBLIC_KEY".encode())

        public_key_data = client_socket.recv(4096)
        client_socket.close()

        return serialization.load_pem_public_key(public_key_data)

    def encrypt_message(self, message):
        encrypted = self.public_key.encrypt(
            message.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return base64.b64encode(encrypted).decode()


# ====================== CLIENTE ======================

class PAM5Client:
    def __init__(self, server_ip="127.0.0.1", server_port=5050):
        self.server_ip = server_ip
        self.server_port = server_port
        self.rsa = RSAClient(server_ip, server_port)

    def send(self, message):
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((self.server_ip, self.server_port))

        encrypted_message = self.rsa.encrypt_message(message)
        client_socket.sendall(encrypted_message.encode())

        client_socket.close()
        print(f"Mensagem '{message}' enviada com sucesso!")


# ====================== INTERFACE GRÁFICA DO CLIENTE ======================

class ClientInterface(tk.Tk):
    def __init__(self):
        super().__init__()

        self.title("Cliente PAM5")
        self.geometry("400x300")

        self.label = tk.Label(self, text="Digite sua mensagem:")
        self.label.pack(pady=10)

        self.message_entry = tk.Entry(self, width=40)
        self.message_entry.pack(pady=10)

        self.send_button = tk.Button(self, text="Enviar Mensagem", command=self.send_message)
        self.send_button.pack(pady=10)

        self.status_label = tk.Label(self, text="")
        self.status_label.pack(pady=10)

    def send_message(self):
        message = self.message_entry.get()
        if message:
            server_ip = "127.0.0.1"  # Substituir pelo IP real do servidor
            client = PAM5Client(server_ip)
            client.send(message)
            self.status_label.config(text=f"Mensagem enviada: {message}")
        else:
            messagebox.showwarning("Aviso", "Por favor, insira uma mensagem!")


if __name__ == "__main__":
    app = ClientInterface()
    app.mainloop()
