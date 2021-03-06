from base64 import b64encode, b64decode
from binascii import Error
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

from cryptosploit.cprint import Printer
from cryptosploit_modules import BaseModule


class AESModule(BaseModule):
    def __init__(self):
        super().__init__()
        self.env.check_var = self.check_var

    def check_var(self, name, value):
        def is_valid_base64(value):
            try:
                return b64decode(value)
            except Error:
                return False
        match name:
            case "aes_mode":
                if value not in ["ECB", "CBC", "OFB"]:
                    return False, "Mode must be ECB/CBC/OFB"
            case "iv":
                if not (value := is_valid_base64(value)):
                    return False, "Value of initialization vector is not a valid base64"
                if len(value) != 16:
                    return False, "Initialization vector must be 16 bytes"
            case "key":
                if not (value := is_valid_base64(value)):
                    return False, "Value of key is not a valid base64"
                if len(value) * 8 not in [128, 192, 256]:
                    return False, "Key length must be 128/192/256 bits"
            case "mode":
                if value not in ["decrypt", "encrypt"]:
                    return False, "Mode can be only decrypt/encrypt"
        return True, ""

    def run(self):
        key = self.env.get_var("key").value
        if not key:
            key = get_random_bytes(32)
        else:
            key = b64decode(key)
        aes_mode = self.env.get_var("aes_mode").value
        res = {"key": b64encode(key).decode()}
        if aes_mode == "ECB":
            cipher = AES.new(key, getattr(AES, f"MODE_{aes_mode}"))
        else:
            iv = self.env.get_var("iv").value
            if iv:
                iv = b64decode(iv)
                cipher = AES.new(key, getattr(AES, f"MODE_{aes_mode}"), iv=iv)
            else:
                cipher = AES.new(key, getattr(AES, f"MODE_{aes_mode}"))
                iv = cipher.iv
            res["iv"] = b64encode(iv).decode()
        if self.env.get_var("mode").value == "encrypt":
            res["res"] = b64encode(
                cipher.encrypt(pad(b64decode(self.env.get_var("plaintext").value), AES.block_size))
            ).decode()
        else:
            res["res"] = b64encode(
                unpad(cipher.decrypt(b64decode(self.env.get_var("plaintext").value)), AES.block_size)
            ).decode()
        Printer.positive(str(res))


module = AESModule
