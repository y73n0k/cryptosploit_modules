import string

from cryptosploit_modules import BaseModule
from cryptosploit.exceptions import ModuleError


class Rot(BaseModule):
    def encrypt(self):
        plaintext = ""
        key = int(self.env.get_var("key").value)
        alphabet = self.env.get_var("alphabet").value
        for letter in self.env.get_var("input").value:
            if letter in alphabet:
                plaintext += alphabet[(alphabet.find(letter) + key) % len(alphabet)]
            else:
                plaintext += letter
        print("[OUTPUT]", plaintext)

    def decrypt(self):
        key = self.env.get_var("key").value
        self.env.set_var("key", "-" + key)
        self.encrypt()
        self.env.set_var("key", key)

    def attack(self):
        ...

    def run(self):
        if not self.env.get_var("key").value.isdigit():
            print("Key must be a natural number!")
        match self.env.get_var("mode").value:
            case "attack":
                self.attack()
            case "decrypt":
                self.decrypt()
            case "encrypt":
                self.encrypt()
            case _:
                raise ModuleError("No such mode!")


module = Rot()
