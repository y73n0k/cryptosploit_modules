from cryptosploit_modules import BaseModule
from cryptosploit.exceptions import ArgError
from os import getcwd
from os.path import join, dirname
from sys import path

flags = {"key_len": "-l {}", "plain_text": "-p {}", "most_frequent_char": "-c {}"}


class Xortool(BaseModule):
    command_start: str = "xortool"

    def __init__(self):
        super().__init__()
        self.env.check_var = self.check_var

    @staticmethod
    def check_var(name, value):
        match name:
            case "mode":
                if value in ("xortool", "help", "advanced"):
                    return True, ""
                return False, f"Possible values: xortool/help/advanced"

            case "xored_file":
                return BaseModule.check_file(value)

            case "key_len":
                try:
                    int(value)
                except ValueError:
                    return False, "Must be an integer"
                return True, ""

            case "most_frequent_char":
                try:
                    if len(value) == 1:
                        return True, ""
                    int(value, 16)
                except ValueError:
                    return False, "Must be a single character or hex"
                return True, ""

            case "plain_text" | "extra_flags":
                return True, ""

    def help_command(self):
        return self.command_start + " --help"

    def xortool_command(self):
        command = self.command_start
        if xored_file := self.env.get_var("xored_file").value:
            to_add = set(iter(self.env)) - {"extra_flags", "mode", "xored_file"}
            for var in to_add:
                if value := self.env.get_var(var).value:
                    command += " " + flags[var].format(value)
            if extra_flags := self.env.get_var("extra_flags").value:
                command += " " + extra_flags
            return command + " " + xored_file
        raise ArgError("Not enough variables to crack. (xored_file))")

    def advanced_command(self):
        flags = self.env.get_var("extra_flags").value
        if flags:
            return self.command_start + " " + flags
        else:
            raise ArgError("Variable 'extra_flags' must be set")

    def run(self):
        func = getattr(self, self.env.get_var("mode").value + "_command")
        command = func()
        self.command_exec(command, {"PYTHONPATH": ":".join(path)})
        if func.__name__.startswith("xortool") or func.__name__.startswith("advanced"):
            self.command_exec(
                f"test -d {join(dirname(__file__))}/xortool_out && mv {join(dirname(__file__))}/xortool_out {getcwd()}",
                {"PYTHONPATH": ":".join(path)},
            )


module = Xortool
