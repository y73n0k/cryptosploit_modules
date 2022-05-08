from binascii import Error
from codecs import encode, decode
from os.path import isfile

from cryptosploit.cprint import Printer
from cryptosploit_modules import BaseModule
from cryptosploit.exceptions import ArgError


class Hex(BaseModule):
    def __init__(self):
        super().__init__()
        self.env.check_var = self.check_var

    @staticmethod
    def check_var(name, value):
        """Must return isvalid_variable: bool, error_msg: str"""
        match name:
            case "mode":
                if value in ("to_hex", "from_hex"):
                    return True, ""
                return False, "May be to_hex/from_hex"
            case "input":
                if len(bytes(value, encoding="utf-8")) == len(value):
                    return True, ""
                return (
                    False,
                    "Your string must be a utf-8 string or path to the file to be processed",
                )
            case _:
                return True, ""

    def to_hex_command(self, inp, delimiter):
        if isfile(inp):
            with open(inp) as f:
                inp = f.read()
        inp = bytes(inp, encoding="utf-8")
        output = encode(inp, "hex").decode("utf-8")
        output = delimiter + delimiter.join(
            [output[i : i + 2] for i in range(0, len(output), 2)]
        )
        Printer.positive("Encoded string:\n" + output)

    def from_hex_command(self, inp, delimiter):
        if isfile(inp):
            with open(inp) as f:
                inp = f.read()
        inp = bytes("".join(inp.split(delimiter)), encoding="utf-8")
        try:
            output = decode(inp, "hex")
        except Error as err:
            raise ArgError("Your input is not valid hex string") from err
        Printer.positive("Decoded string:\n" + output.decode("utf-8"))

    def run(self):
        inp = self.env.get_var("input").value
        delimiter = self.env.get_var("delimiter").value
        if inp:
            if (
                delimiter.startswith('"')
                and delimiter.endswith('"')
                and len(delimiter) > 1
            ):
                delimiter = delimiter[1:-1]
            func = getattr(self, self.env.get_var("mode").value + "_command")
            return func(inp, delimiter)
        raise ArgError("Input must be set")


module = Hex
