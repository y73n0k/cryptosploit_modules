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
            case "mode":
                if value in ("encode", "decode"):
                    return True, ""
                return False, "May be decode/encode"
            case _:
                return True, ""

    def encode_command(self, inp):
        text = b85encode(inp.encode()).decode()
        Printer.positive("Encoded string:\n" + text)

    def decode_command(self, inp):
        try:
            text = b85decode(inp.encode()).decode()
        except (ValueError, Error) as err:
            raise ArgError("Your input is not valid base85 string") from err
        else:
            Printer.positive("Decoded string:\n" + text)

    def run(self):
        inp = self.env.get_var("input").value
        if isfile(inp):
            with open(inp) as f:
                inp = f.read()
        if inp:
            func = getattr(self, self.env.get_var("mode").value + "_command")
            return func(inp)
        raise ArgError("All variables must be set")


module = Base85
