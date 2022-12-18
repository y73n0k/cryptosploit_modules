from cryptosploit_modules import BaseModule
from cryptosploit.exceptions import ArgError
from os import getcwd
from sys import path


class Ciphey(BaseModule):
    command_start: str = "docker run -it --rm -v {}:/home/nonroot/workdir remnux/ciphey"

    def __init__(self):
        super().__init__()
        self.env.check_var = self.check_var

    @staticmethod
    def check_var(name, value):
        match name:
            case "mode":
                if value in ("help", "basic", "advanced"):
                    return True, ""
                return False, "Possible values: 'help', 'basic', 'advanced'"

            case "input_type":
                if value in ("text", "file"):
                    return True, ""
                return False, "Possible values: 'text', 'file'"

            case "encrypted_file":
                return BaseModule.check_file(value)

            case "text" | "extra_flags":
                return True, ""

    def help_command(self):
        return self.command_start.format(getcwd()) + " --help"

    def basic_command(self):
        command = self.command_start.format(getcwd())
        match self.env.get_var("input_type").value:
            case "text":
                if text := self.env.get_var("text").value:
                    command += " -t " + text
                else:
                    raise ArgError("Variable 'text' must be set")

            case "file":
                if encrypted_file := self.env.get_var("encrypted_file").value:
                    command += " -f " + encrypted_file
                else:
                    raise ArgError("Variable 'encrypted_file' must be set")

        if extra_flags := self.env.get_var("extra_flags").value:
            command += " " + extra_flags
        return command

    def advanced_command(self):
        flags = self.env.get_var("extra_flags").value
        if flags:
            return self.command_start.format(getcwd()) + " " + flags
        else:
            raise ArgError("Variable 'extra_flags' must be set")

    def run(self):
        func = getattr(self, self.env.get_var("mode").value + "_command")
        command = func()
        self.command_exec(command, {"PYTHONPATH": ":".join(path)})


module = Ciphey
