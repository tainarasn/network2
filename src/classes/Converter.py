# Conversão de Dados
class Converter:
    @staticmethod
    def text_to_binary(text):
        """Converte um texto para binário usando ASCII estendido."""
        return ''.join(format(ord(char), '08b') for char in text)

    @staticmethod
    def binary_to_text(binary):
        """Converte um binário de volta para texto usando ASCII estendido."""
        return ''.join(chr(int(binary[i:i+8], 2)) for i in range(0, len(binary), 8))
