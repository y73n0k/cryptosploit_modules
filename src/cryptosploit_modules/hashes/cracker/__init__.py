from cryptosploit_modules import BaseModule
from cryptosploit.exceptions import ModuleError, ArgError
from os.path import exists
from sys import path

from .hash_identifier import identify_hash, prettify_hash_info


class Cracker(BaseModule):
    allowed_crackers: tuple[str, str] = ("hashcat", "john")

    def __init__(self):
        super().__init__()
        self.env.check_var = self.check_var
        self.last_hash_file: str | None = None
        self.hash_types: dict | None = None

    @staticmethod
    def check_var(name, value):
        match name:
            case "default_cracker":
                if value in Cracker.allowed_crackers:
                    return True, ""
                return False, f"Possible values: hashcat/john"

            case "hash_file" | "wordlist":
                return BaseModule.check_file(value)

            case "mode":
                for i in ("crack", "help", "advanced"):
                    if value == i:
                        return True, ""
                return False, f"Possible values: crack/help/advanced"

            case "path_to_binary":
                if exists(value):
                    for i in Cracker.allowed_crackers:
                        if i in value:
                            return True, ""
                    return False, "Must contain hashcat/john"
                return False, "No such path!"

            case "identify_hash_type":
                if value.lower() in ("true", "false"):
                    return True, ""
                return False, "Possible values: true/false"

            case _:
                return True, ""

    def command_generator(self):
        """Generate path to binary"""
        return (
            self.env.get_var("path_to_binary").value
            or self.env.get_var("default_cracker").value
        )

    def help_command(self):
        return self.command_generator() + " --help"

    def crack_command(self):
        hash_mode = self.env.get_var("hash_mode").value
        hash_file = self.env.get_var("hash_file").value
        wordlist = self.env.get_var("wordlist").value
        extra_flags = self.env.get_var("extra_flags").value.strip()
        identify_mode = self.env.get_var("identify_hash_type").value

        if hash_file and wordlist:
            command = self.command_generator()

            if identify_mode.lower() == "true":

                if self.last_hash_file != hash_file:
                    self.last_hash_file = hash_file
                    self.hash_types = identify_hash(hash_file)
                print(*prettify_hash_info(self.hash_types))
                key = next(iter(self.hash_types))
                hash_mode = (
                    self.hash_types[key][0]["hashcat"]
                    if "hashcat" in command
                    else self.hash_types[key][0]["john"]
                )
                del self.hash_types[key][0]
            if hash_mode != "":
                if "hashcat" in command:
                    command += f" -a 0 -m {hash_mode} {hash_file} {wordlist}"
                else:
                    command += (
                        f" --format={hash_mode} --wordlist={wordlist} {hash_file}"
                    )
                return command + " " + extra_flags

        raise ArgError("Not enough variables to crack.")

    def advanced_command(self):
        flags = " " + self.env.get_var("extra_flags").value
        if flags:
            return self.command_generator() + flags
        else:
            raise ArgError("Variable 'extra_flags' must be set")

    def run(self):
        func = getattr(self, self.env.get_var("mode").value + "_command")
        command = func()
        self.command_exec(
            command,
            {"PYTHONPATH": ":".join(path)}
        )


module = Cracker()
