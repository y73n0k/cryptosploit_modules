import string

from cryptosploit_modules import BaseModule
from cryptosploit.exceptions import ModuleError


class Rot(BaseModule):
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
        result = self.encrypt()
        return result

    def run(self):
        if not self.env.get_var("key").value.isdigit():
            print("Key must be a natural number!")
        try:
            func = getattr(self, self.env.get_var("mode").value)
            result = func()
            print("[OUTPUT]", result)
        except AttributeError:
            raise ModuleError("No such mode!")


module = Rot()
