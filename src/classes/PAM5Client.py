import socket 
import Converter
import PAM5Coder


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
