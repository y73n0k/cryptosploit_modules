import string
from re import compile

from cryptosploit_modules import BaseModule
from cryptosploit.cprint import Printer
from cryptosploit.exceptions import ModuleError, ArgError


class Rot(BaseModule):
    def __init__(self):
        super().__init__()
        self.env.check_var = self.check_var

    @staticmethod
    def check_var(name, value):
        match name:
            case "mode":
                if value in ("attack", "decrypt", "encrypt"):
                    return True, ""
                return False, "May be attack/decrypt/encrypt"
            case "key":
                if not value.isdigit():
                    return False, "Key must be a natural number!"
                return True, ""
            case _:
                return True, ""

    def encrypt(self):
        result = ""
        key = int(self.env.get_var("key").value)
        alphabet = self.env.get_var("alphabet").value.upper()
        inp = self.env.get_var("input").value
        for ind, char in enumerate(inp.upper()):
            if char in alphabet:
                res_char = alphabet[(alphabet.find(char) + key) % len(alphabet)]
                result += res_char if inp[ind].isupper() else res_char.lower()
            else:
                result += char
        return result

    def decrypt(self):
        key = self.env.get_var("key").value
        self.env.set_var("key", "-" + key)
        result = self.encrypt()
        self.env.set_var("key", key)
        return result

    def attack(self):
        results = []
        pattern = compile(self.env.get_var("contains").value or ".*")
        alphabet = self.env.get_var("alphabet").value.upper()
        for alphabet in [
            alphabet,
            string.ascii_uppercase,
            string.ascii_uppercase + string.digits,
            string.ascii_uppercase + string.digits + string.punctuation,
        ]:
            for key in range(len(alphabet)):
                self.env.set_var("key", str(key))
                if pattern.match(r := self.decrypt()):
                    results.append(r)
        return "\n".join(set(results))

    def run(self):
        func = getattr(self, self.env.get_var("mode").value)
        result = func()
        if result:
            Printer.positive("Result:\n" + result)
        else:
            Printer.negative("Result:\nNone")


module = Rot()
