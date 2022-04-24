from math import gcd
from os.path import isfile
from re import compile

from cryptosploit.cprint import Printer
from cryptosploit_modules import BaseModule


class Affine(BaseModule):
    def __init__(self):
        super().__init__()
        self.env.check_var = self.check_var

    def check_var(self, name, value):
        match name:
            case "key":
                if not value.isdigit():
                    return False, "Value must be a natural number!"
                if (
                    gcd(
                        len(self.env.get_var("alphabet").value),
                        int(value),
                    )
                    != 1
                ):
                    return False, "Key must be coprime with alphabet length"
            case "offset":
                if not value.isdigit():
                    return False, "Value must be a natural number!"
            case "mode":
                if value not in ("decrypt", "encrypt", "attack"):
                    return False, "No such mode!"
            case "alphabet":
                if (
                    gcd(
                        len(value),
                        int(self.env.get_var("key").value),
                    )
                    != 1
                ):
                    return False, "Alphabet length must be coprime with key"
        return True, ""

    def encrypt(self):
        result = ""
        key = int(self.env.get_var("key").value)
        offset = int(self.env.get_var("offset").value)
        alphabet = self.env.get_var("alphabet").value.upper()
        inp = self.env.get_var("input").value
        if isfile(inp):
            with open(inp) as f:
                inp = f.read()
        for ind, char in enumerate(inp.upper()):
            if char in alphabet:
                res_char = alphabet[
                    (key * alphabet.find(char) + offset) % len(alphabet)
                ]
                result += res_char if inp[ind].isupper() else res_char.lower()
            else:
                result += char
        return result

    def decrypt(self):
        result = ""
        key = int(self.env.get_var("key").value)
        offset = int(self.env.get_var("offset").value)
        alphabet = self.env.get_var("alphabet").value.upper()
        key = pow(key, -1, len(alphabet))
        inp = self.env.get_var("input").value
        if isfile(inp):
            with open(inp) as f:
                inp = f.read()
        for ind, char in enumerate(inp.upper()):
            if char in alphabet:
                res_char = alphabet[
                    (key * (alphabet.find(char) - offset)) % len(alphabet)
                ]
                result += res_char if inp[ind].isupper() else res_char.lower()
            else:
                result += char
        return result

    def attack(self):
        results = []
        contains = self.env.get_var("contains").value
        if isfile(contains):
            with open(contains) as f:
                contains = f.read()
        pattern = compile(contains or ".*")
        alphabet = self.env.get_var("alphabet").value.upper()
        prev_key, prev_offset = (
            self.env.get_var("key").value,
            self.env.get_var("offset").value,
        )
        for key in range(1, len(alphabet)):
            if gcd(key, len(alphabet)) == 1:
                self.env.set_var("key", str(key))
                for offset in range(len(alphabet)):
                    self.env.set_var("offset", str(offset))
                    if pattern.match(r := self.decrypt()):
                        results.append(r)
        self.env.set_var("key", prev_key)
        self.env.set_var("offset", prev_offset)
        return "\n".join(set(results))

    def run(self):
        func = getattr(self, self.env.get_var("mode").value)
        result = func()
        if result:
            Printer.positive("Result:\n" + result)
        else:
            Printer.negative("Result:\nNone")


module = Affine()
