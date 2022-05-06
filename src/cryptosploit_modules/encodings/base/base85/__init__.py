from base64 import b85encode, b85decode
from binascii import Error
from os.path import isfile

from cryptosploit.cprint import Printer
from cryptosploit.exceptions import ArgError
from cryptosploit_modules import BaseModule


class Base85(BaseModule):
    def __init__(self):
        super().__init__()
        self.env.check_var = self.check_var

    @staticmethod
    def check_var(name, value):
        match name:
            case "input":
                if len(bytes(value, encoding="utf-8")) == len(value):
                    return True, ""
                return (
                    False,
                    "Your string must be a utf-8 string or path to the file to be processed",
                )
            case "mode":
                if value in ("encode", "decode"):
                    return True, ""
                return False, "May be decode/encode"

    def encode_command(self, inp):
        if isfile(inp):
            with open(inp) as f:
                inp = f.read()
        text = bytes(inp, encoding="utf-8")
        Printer.positive("Encoded string:\n" + b85encode(text).decode())

    def decode_command(self, inp):
        if isfile(inp):
            with open(inp) as f:
                inp = f.read()
        text = bytes(inp, encoding="utf-8")
        try:
            Printer.positive("Decoded string:\n" + b85decode(text).decode())
        except Error as err:
            raise ArgError("Your input is not valid base85 string") from err

    def run(self):
        inp = self.env.get_var("input").value
        if inp:
            func = getattr(self, self.env.get_var("mode").value + "_command")
            return func(inp)
        raise ArgError("All variables must be set")


module = Base85
