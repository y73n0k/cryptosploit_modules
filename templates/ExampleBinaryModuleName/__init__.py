"""
Template for other programming languages.
To check full module directory structure (config.json, do_install.sh)
visit our github https://github.com/y73n0k/cryptosploit_modules
"""

from cryptosploit.cprint import Printer
from cryptosploit_modules import BaseModule

class ExampleBinaryModuleName(BaseModule):
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

    def run(self):
        """
        A function that is called when the user
        uses the run command
        """
        key = self.env.get_var("key").value
        ciphertext = self.env.get_var("ciphertext").value
        if key and ciphertext:
            return self.command_exec(f"your_binary -k {key} -ct {ciphertext}")
        return Printer.error("All paramaters must be set")


module = ExampleBinaryModuleName
