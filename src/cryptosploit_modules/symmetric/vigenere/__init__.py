from itertools import cycle

from cryptosploit_modules import BaseModule
from cryptosploit.cprint import Printer


class Vigenere(BaseModule):
    def __init__(self):
        super().__init__()
        self.env.check_var = self.check_var

    def check_var(self, name, value):
        match name:
            case "mode":
                if value in ("decrypt", "encrypt"):
                    return True, ""
                return False, "May be decrypt/encrypt"
            case "key":
                alphabet = set(self.env.get_var("alphabet"))
                if not all((c in alphabet for c in value)):
                    return False, "Key must contains only alphabet symbols"
                return True, None
            case _:
                return True, ""

    def encrypt(self):
        result = ""
        key = int(self.env.get_var("key").value)
        alphabet = self.env.get_var("alphabet").value.upper()
        inp = self.env.get_var("input").value
        d = {c: i for i, c in enumerate(alphabet)}
        for m, k in zip(inp, cycle(key)):
            res += alphabet[(d[m] + d[k]) % len(alphabet)]
        return result

    def decrypt(self):
        result = ""
        key = int(self.env.get_var("key").value)
        alphabet = self.env.get_var("alphabet").value.upper()
        inp = self.env.get_var("input").value
        d = {c: i for i, c in enumerate(alphabet)}
        for c, k in zip(inp, cycle(key)):
            res += alphabet[(d[c] - d[k]) % len(alphabet)]
        return result

    def run(self):
        func = getattr(self, self.env.get_var("mode").value)
        result = func()
        if result:
            Printer.positive("Result:\n" + result)
        else:
            Printer.negative("Result:\nNone")


module = Vigenere
