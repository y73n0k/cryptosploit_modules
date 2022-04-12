from cryptosploit_modules import BaseModule
from cryptosploit.exceptions import ModuleError, ArgError
from subprocess import Popen, PIPE
from os import path


class Cracker(BaseModule):
    allowed_crackers = ("hashcat", "john")

    def __init__(self):
        super().__init__()
        self.env.check_var = self.check_var

    @staticmethod
    def command_exec(command):
        print(f"[*] Executing '{command}'")
        proc = Popen(command, stderr=PIPE, shell=True, stdin=PIPE, stdout=PIPE, universal_newlines=True, text=True)
        for line in iter(proc.stdout.readline, ""):
            print(line, end="")
        proc.stdout.close()
        for line in iter(proc.stderr.readline, ""):
            print(line, "\n")
        proc.stderr.close()

    @staticmethod
    def check_var(name, value):
        def check_file(filename):
            try:
                open(filename).close()
                return True, ""
            except (FileNotFoundError, IsADirectoryError, OSError) as err:
                return False, err.strerror
        match name:
            case "default_cracker":
                if value in Cracker.allowed_crackers:
                    return True, ""
                return False, f"[!] Possible values: hashcat/john\nYour input: {value}"
            case "mode":
                for i in ("crack", "help", "advanced"):
                    if value == i:
                        return True, ""
                return False, f"[!] Possible values: crack/help/advanced\nYour input: {value}"
            case "hash_file":
                return check_file(value)
            case "wordlist":
                return check_file(value)
            case "path_to_binary":
                if path.exists(value):
                    for i in Cracker.allowed_crackers:
                        if i in value:
                            return True, ""
                    return False, "[!] Must contain hashcat/john"
                return False, "[!] No such path!"
            case _:
                return True, ""

    def command_generator(self):
        return self.env.get_var("path_to_binary").value or self.env.get_var("default_cracker").value

    def help_command(self):
        return self.command_exec(self.command_generator() + " --help")

    def crack_command(self):
        hash_mode = self.env.get_var("hash_mode").value
        hash_file = self.env.get_var("hash_file").value
        wordlist = self.env.get_var("wordlist").value

        if all((hash_mode, hash_file, wordlist)):
            command = self.command_generator()
            if "hashcat" in command:
                command += f" -a 0 -m {hash_mode} {hash_file} {wordlist}"
                self.command_exec(command)
            else:
                command += f" --format={hash_mode} --wordlist={wordlist} {hash_file}"
                self.command_exec(command)
        else:
            raise ArgError("[!] Not enough variables to crack.")

    def advanced_command(self):
        flags = self.env.get_var("extra_flags").value
        if flags:
            return self.command_exec(self.command_generator() + flags)
        else:
            raise ArgError("[!] extra_flags must be set")

    def run(self):
        try:
            func = getattr(self, self.env.get_var("mode").value + "_command")
            return func()
        except AttributeError:
            raise ModuleError("No such mode!")


module = Cracker()
