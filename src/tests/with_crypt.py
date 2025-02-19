 #====================== SERVIDOR ======================
import tkinter as tk
from tkinter import messagebox
import threading
import socket
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

    def decrypt_message(self, encrypted_message):
        decrypted = self.private_key.decrypt(
            base64.b64decode(encrypted_message),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return decrypted.decode()

class PAM5Server:
    def __init__(self, host="0.0.0.0", port=5050, rsa=None, gui_callback=None):
        self.host = host
        self.port = port
        self.rsa = rsa
        self.gui_callback = gui_callback

    def start(self):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind((self.host, self.port))
        server_socket.listen(1)
        print(f"Servidor aguardando conexão na porta {self.port}...")

        while True:
            conn, addr = server_socket.accept()
            print(f"Conexão estabelecida com {addr}")

            encrypted_message = conn.recv(4096).decode()
            print(f"Mensagem recebida (criptografada): {encrypted_message}")

            if encrypted_message == "GET_PUBLIC_KEY":
                print("Enviando chave pública para o cliente...")
                conn.sendall(self.rsa.public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ))
                conn.close()
                continue

            decrypted_message = self.rsa.decrypt_message(encrypted_message)
            print(f"Mensagem recebida: {decrypted_message}")
            if self.gui_callback:
                self.gui_callback(decrypted_message)
            conn.close()

class ServerInterface(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Servidor PAM5")
        self.geometry("400x300")
        self.rsa = RSAEncryption()
        self.server = PAM5Server(gui_callback=self.update_received_message, rsa=self.rsa)
        self.label = tk.Label(self, text="Aguardando mensagens...")
        self.label.pack(pady=20)
        self.start_button = tk.Button(self, text="Iniciar Servidor", command=self.start_server)
        self.start_button.pack(pady=10)
        self.text_output = tk.Label(self, text="", wraplength=350)
        self.text_output.pack(pady=10)

    def start_server(self):
        server_thread = threading.Thread(target=self.server.start, daemon=True)
        server_thread.start()
        messagebox.showinfo("Servidor", "Servidor iniciado e aguardando conexões!")

    def update_received_message(self, message):
        self.text_output.config(text=f"Mensagem recebida: {message}")

if __name__ == "__main__":
    app = ServerInterface()
    app.mainloop()