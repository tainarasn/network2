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

def convert_from_pam5(pam5_signal):
    # Aqui você deve implementar a lógica para converter o sinal PAM5 de volta ao binário
    return pam5_signal  # Retorne o binário adequado

def start_server(host='0.0.0.0', port=5050):
    rsa = RSAEncryption()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((host, port))
        server_socket.listen()
        print("Servidor aguardando conexão na porta 5050...")

        while True:
            conn, addr = server_socket.accept()
            with conn:
                print(f"Conexão estabelecida com {addr}")
                pam5_signal = conn.recv(1024).decode()
                print(f"Sinal PAM5 recebido: {pam5_signal}")

                # Converter o sinal PAM5 de volta ao binário
                binary_message = convert_from_pam5(pam5_signal)

                # Descriptografar a mensagem
                try:
                    decrypted_message = rsa.decrypt_message(binary_message)
                    print(f"Mensagem descriptografada: {decrypted_message}")
                except Exception as e:
                    print(f"Erro ao descriptografar: {e}")

if __name__ == "__main__":
    start_server()
