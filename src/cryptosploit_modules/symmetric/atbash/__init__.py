from cryptosploit_modules import BaseModule
from os.path import isfile


class Atbash(BaseModule):
    def __init__(self):
        super().__init__()
        self.env.check_var = self.check_var

    def check_var(self, name, value):
        match name:
            case "mode":
                if value not in ("decrypt", "encrypt"):
                    return False, "No such mode!"
        return True, ""

    def encrypt(self):
        result = ""
        alphabet = self.env.get_var("alphabet").value.upper()
        d = dict(zip(alphabet, alphabet[::-1]))
        inp = self.env.get_var("input").value
        if isfile(inp):
            with open(inp) as f:
                inp = f.read()
        for ind, char in enumerate(inp.upper()):
            if char in d:
                res_char = d[char]
                result += res_char if inp[ind].isupper() else res_char.lower()
            else:
                result += char
        return result

    def decrypt(self):
        return self.encrypt()

    def run(self):
        func = getattr(self, self.env.get_var("mode").value)
        result = func()
        print(*("[+] Result:\n", result) if result else "[-] Result:\nNone", sep="")


module = Atbash()
