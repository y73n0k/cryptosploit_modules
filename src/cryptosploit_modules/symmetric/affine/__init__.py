from math import gcd
from re import compile

from cryptosploit_modules import BaseModule
from cryptosploit.exceptions import ModuleError, ArgError


class Affine(BaseModule):
    def encrypt(self):
        result = ""
        key = int(self.env.get_var("key").value)
        offset = int(self.env.get_var("offset").value)
        alphabet = self.env.get_var("alphabet").value.upper()
        inp = self.env.get_var("input").value
        for ind, char in enumerate(inp.upper()):
            if char in alphabet:
                res_char = alphabet[(key * alphabet.find(char) + offset) % len(alphabet)]
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
        for ind, char in enumerate(inp.upper()):
            if char in alphabet:
                res_char = alphabet[(key * (alphabet.find(char) - offset)) % len(alphabet)]
                result += res_char if inp[ind].isupper() else res_char.lower()
            else:
                result += char
        return result

    def attack(self):
        results = []
        pattern = compile(self.env.get_var("contains").value or ".*")
        alphabet = self.env.get_var("alphabet").value.upper()
        for key in range(len(alphabet)):
            if gcd(key, len(alphabet)) == 1:
                self.env.set_var("key", str(key))
                for offset in range(len(alphabet)):
                    self.env.set_var("offset", str(offset))
                    if pattern.match(r := self.decrypt()):
                        results.append(r)
        return "\n".join(set(results))

    def run(self):
        if not self.env.get_var("key").value.isdigit():
            raise ArgError("Key must be a natural number!")
        if not self.env.get_var("offset").value.isdigit():
            raise ArgError("Offset must be a natural number!")
        if gcd(len(self.env.get_var("alphabet").value), int(self.env.get_var("key").value)) != 1:
            raise ModuleError("Key must be coprime with alphabet length")
        try:
            func = getattr(self, self.env.get_var("mode").value)
            result = func()
            print(*("[+] Result:\n", result) if result else "[-] Result:\nNone", sep="")
        except AttributeError:
            raise ModuleError("No such mode!")


module = Affine()
