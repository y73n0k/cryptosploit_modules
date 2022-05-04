from base64 import b32encode, b32decode
from binascii import Error
from cryptosploit.cprint import Printer
from cryptosploit.exceptions import ArgError
from cryptosploit_modules import BaseModule
from os.path import isfile

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
                return False, "Your string must be a utf-8 string or or path to the file to be processed"
            case "mode":
                if value in ("encode", "decode"):
                    return True, ""
                return False, "May be decode/encode"

    def encode_command(self, inp):
        if isfile(inp):
            with open(inp) as f:
                inp = f.read()
        text = bytes(inp, encoding="utf-8")
        Printer.positive("Encoded string:\n" + b32encode(text).decode())


    def decode_command(self, inp):
        if isfile(inp):
            with open(inp) as f:
                inp = f.read()
        text = bytes(inp, encoding="utf-8")
        try:
            Printer.positive("Decoded string:\n" + b32decode(text).decode())
        except Error as err:
            raise ArgError from err
        

    def run(self):
        mode = self.env.get_var("mode").value
        inp = self.env.get_var("input").value
        if mode:
            func = getattr(self, mode + "_command")
            return func(inp)
        else:
            raise ArgError("All variables must be set")


module = Base32
