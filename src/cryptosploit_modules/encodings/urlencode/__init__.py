from urllib.parse import unquote, quote

from cryptosploit.cprint import Printer
from cryptosploit.exceptions import ArgError
from cryptosploit_modules import BaseModule


class UrlEncoder(BaseModule):
    def __init__(self):
        super().__init__()
        self.env.check_var = self.check_var

    @staticmethod
    def check_var(name, value):
        """Must return isvalid_variable: bool, error_msg: str"""
        match name:
            case "mode":
                if value in ("encode", "decode"):
                    return True, ""
                return False, "May be encode/decode"
            case "input":
                if len(bytes(value, encoding="utf-8")) == len(value):
                    return True, ""
                return (
                    False,
                    "Your string must be a utf-8 string to be processed",
                )
            case _:
                return True, ""

    def encode_command(self, inp):
        safe_chars = self.env.get_var("safe_chars").value
        try:
            Printer.positive("Encoded string:\n" + quote(inp, safe=safe_chars or "/:?=", encoding="utf-8"))
        except UnicodeEncodeError as err:
            raise ArgError("Your string must be a utf-8 string") from err

    def decode_command(self, inp):
        try:
            Printer.positive("Decoded string:\n" + unquote(inp, encoding="utf-8"))
        except UnicodeDecodeError as err:
            raise ArgError("Your string must be a utf-8 string") from err

    def run(self):
        mode = self.env.get_var("mode").value
        inp = self.env.get_var("input").value
        if mode and inp:
            func = getattr(self, self.env.get_var("mode").value + "_command")
            return func(inp)
        raise ArgError("All variables must be set")


module = UrlEncoder
