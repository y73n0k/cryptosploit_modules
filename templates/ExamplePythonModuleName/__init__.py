"""
Template for python modules
To check full module directory structure (config.json, do_install.sh)
visit our github: https://github.com/y73n0k/cryptosploit_modules
"""

from cryptosploit.cprint import Printer
from cryptosploit_modules import BaseModule

class ExamplePythonModuleName(BaseModule):
    def __init__(self):
        super().__init__()
        self.env.check_var = self.check_var

    @staticmethod
    def check_var(name, value):
        """Must return isvalid_variable: bool, error_msg: str"""
        match name:
            case "key":
                if value.isdigit():
                    return True, ""
                return False, "Must be a digit"
            case _:
                return True, ""

    def encrypt_command(self):
       """Encrypt function"""

    def decrypt_command(self):
       """Decrypt function"""

    def attack_command(self):
       """Attack cipher function"""

    def run(self):
        """
        A function that is called when the user
        uses the run command
        """
        func = getattr(self, self.env.get_var("mode").value + "_command")
        return func()


module = ExamplePythonModuleName
