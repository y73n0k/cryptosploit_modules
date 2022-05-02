from base64 import b32encode, b32decode
from binascii import Error
from cryptosploit.cprint import Printer
from cryptosploit.exceptions import ArgError
from cryptosploit_modules import BaseModule


class Base32(BaseModule):
    def __init__(self):
        super().__init__()
        self.env.check_var = self.check_var

    @staticmethod
    def check_var(name, value):
        match name:
            case "input":
                if len(bytes(value, encoding="utf-8")) == len(value):
                    return True, ""
                return False, "Your string must be a utf-8 string"
            case "mode":
                if value in ("encode", "decode"):
                    return True, ""
                return False, "May be decode/encode"

    def encode_command(self, text):
        Printer.positive("Encoded string:\n" + b32encode(text).decode())

    def decode_command(self, text):
        try:
            Printer.positive("Decoded string:\n" + b32decode(text).decode())
        except Error as err:
            raise ArgError(str(err))

    def run(self):
        text = bytes(self.env.get_var("input").value, encoding="utf-8")
        mode = self.env.get_var("mode").value
        if text and mode:
            func = getattr(self, mode + "_command")
            return func(text)
        else:
            raise ArgError("All variables must be set")


module = Base32
