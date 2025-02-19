import socket
import tkinter as tk
import base64
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

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

def convert_to_binary(encrypted_message):
    return ''.join(format(ord(char), '08b') for char in encrypted_message)

def apply_pam5(binary_message):
    # Exemplo simples de conversão para PAM5
    # Substitua por sua lógica real de conversão para PAM5
    return binary_message  # Retorne o sinal PAM5

class ClientInterface(tk.Tk):
    def __init__(self, server_ip="127.0.0.1", server_port=5050):
        super().__init__()
        self.title("Cliente PAM5")
        self.geometry("500x500")
        self.server_ip = server_ip
        self.server_port = server_port

        self.rsa = RSAEncryption()

        self.label = tk.Label(self, text="Enviar Mensagem:")
        self.label.pack(pady=20)

        self.entry = tk.Entry(self, width=50)
        self.entry.pack(pady=10)

        self.send_button = tk.Button(self, text="Enviar", command=self.send_message)
        self.send_button.pack(pady=10)

    def send_message(self):
        message = self.entry.get()
        if message:
            # Criptografar a mensagem
            encrypted_message = self.rsa.encrypt_message(message)

            # Converter a mensagem criptografada para binário
            binary_message = convert_to_binary(encrypted_message)

            # Aplicar o algoritmo PAM5 ao binário
            pam5_signal = apply_pam5(binary_message)

            # Conectar ao servidor e enviar o sinal PAM5
            self.connect_and_send(pam5_signal)

    def connect_and_send(self, pam5_signal):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
            try:
                client_socket.connect((self.server_ip, self.server_port))
                # Enviar o sinal PAM5
                client_socket.sendall(pam5_signal.encode())
                print("Sinal PAM5 enviado ao servidor!")
            except Exception as e:
                print(f"Erro ao conectar ou enviar: {e}")

if __name__ == "__main__":
    app = ClientInterface(server_ip="127.0.0.1", server_port=5050)
    app.mainloop()
