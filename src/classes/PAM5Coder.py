import numpy as np
import matplotlib.pyplot as plt

# Codificação PAM5
class PAM5Coder:
    pam5_mapping = {
        '0000': -2, '0001': -1, '0010': 0, '0011': 1, '0100': 2,
        '0101': -1.5, '0110': -0.5, '0111': 0.5, '1000': 1.5, '1001': 2.5,
        '1010': -1.25, '1011': -0.75, '1100': 0.25, '1101': 0.75, '1110': 1.25, '1111': 1.75
    }
    
    reverse_map = {v: k for k, v in pam5_mapping.items()}

    @classmethod
    def bin_to_pam5(cls, binary):
        """Converte uma sequência binária para símbolos 4D-PAM5."""
        chunks = [binary[i:i + 4] for i in range(0, len(binary), 4)]
        return [cls.pam5_mapping[chunk] for chunk in chunks]

    @classmethod
    def pam5_to_bin(cls, symbols):
        """Converte símbolos 4D-PAM5 de volta para binário."""
        return ''.join(cls.reverse_map[s] for s in symbols)

# Gráfico da Onda PAM5
class PAM5Graph:
    @staticmethod
    def plot(symbols):
        """Gera um gráfico da forma de onda PAM5."""
        t = np.arange(len(symbols))  # Tempo discreto (um tempo para cada símbolo)
        
        plt.figure(figsize=(10, 4))
        plt.step(t, symbols, where='mid', linestyle='-', marker='o', color='b', label='Sinal PAM5')

        plt.xlabel("Tempo (símbolos)")
        plt.ylabel("Nível de Amplitude")
        plt.title("Forma de Onda 4D-PAM5")
        plt.yticks(sorted(set(symbols)))  # Apenas níveis utilizados
        plt.grid()
        plt.legend()
        plt.show()