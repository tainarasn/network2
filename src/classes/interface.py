import tkinter as tk
from tkinter import scrolledtext
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

class PAM5GUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Comunicação 4D-PAM5")

        # Frame para entrada de mensagem
        self.frame_input = tk.Frame(self.root)
        self.frame_input.pack(pady=10)

        tk.Label(self.frame_input, text="Digite a Mensagem:").pack()
        self.entry_msg = tk.Entry(self.frame_input, width=40)
        self.entry_msg.pack()

        self.btn_send = tk.Button(self.frame_input, text="Enviar", command=self.process_message)
        self.btn_send.pack(pady=5)

        # Área de Exibição das Mensagens
        self.frame_display = tk.Frame(self.root)
        self.frame_display.pack(pady=10)

        self.text_output = scrolledtext.ScrolledText(self.frame_display, width=60, height=10)
        self.text_output.pack()

        # Frame para o gráfico
        self.frame_graph = tk.Frame(self.root)
        self.frame_graph.pack()

        self.figure, self.ax = plt.subplots(figsize=(5, 2))
        self.ax.set_title("Forma de Onda 4D-PAM5")
        self.ax.set_xlabel("Tempo (símbolos)")
        self.ax.set_ylabel("Nível de Amplitude")
        self.ax.grid(True)

        self.canvas = FigureCanvasTkAgg(self.figure, master=self.frame_graph)
        self.canvas.get_tk_widget().pack()

    def process_message(self):
        msg = self.entry_msg.get()
        self.text_output.insert(tk.END, f"Mensagem Original: {msg}\n")

        # Aqui será chamada a criptografia e os outros processos
        # Exemplo:
        msg_encrypted = self.encrypt_message(msg)
        self.text_output.insert(tk.END, f"Mensagem Criptografada: {msg_encrypted}\n")

        # Atualizar o gráfico (exemplo de sinais)
        self.ax.clear()
        self.ax.plot([2, 1.75, -0.5, 0.25, 1.25, -1, 0, -1], marker='o', linestyle='-', color='b')
        self.canvas.draw()

    def encrypt_message(self, msg):
        # Simulação de criptografia (pode ser substituído pelo método real)
        return ''.join(chr(ord(c) + 1) for c in msg)

if __name__ == "__main__":
    root = tk.Tk()
    app = PAM5GUI(root)
    root.mainloop()
