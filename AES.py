import numpy as np
import BitVector


class AES:

    def __init__(self, key: str) -> None:
        super().__init__()
        self.key_plaintext = key

    def encrypt(self, plaintext):
        pass

    def decrypt(self, cyphertext):
        pass


if __name__ == '__main__':
    print('Hello, AES!')
