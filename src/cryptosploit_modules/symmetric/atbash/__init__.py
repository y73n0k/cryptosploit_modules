from cryptosploit_modules import BaseModule
from cryptosploit.exceptions import ModuleError, ArgError


class Atbash(BaseModule):
    def encrypt(self):
        result = ""
        alphabet = self.env.get_var("alphabet").value.upper()
        d = dict(zip(alphabet, alphabet[::-1]))
        inp = self.env.get_var("input").value
        for ind, char in enumerate(inp.upper()):
            if char in d:
                res_char = d[char]
                result += res_char if inp[ind].isupper() else res_char.lower()
            else:
                result += char
        return result

    def decrypt(self):
        alphabet = self.env.get_var("alphabet").value
        self.env.set_var("alphabet", alphabet[::-1])
        result = self.encrypt()
        self.env.set_var("alphabet", alphabet)
        return result

    def run(self):
        try:
            func = getattr(self, self.env.get_var("mode").value)
            result = func()
            print(*("[+] Result:\n", result) if result else "[-] Result:\nNone", sep="")
        except AttributeError:
            raise ModuleError("No such mode!")


module = Atbash()
