from abc import ABCMeta, abstractmethod
from dataclasses import dataclass
from json import load
from os import environ
from os.path import dirname, join, exists, isfile
from subprocess import Popen, PIPE
from sys import modules, stdin
from tabulate import tabulate

from cryptosploit.cprint import Printer, colorize_strings, SGR
from cryptosploit.exceptions import ModuleError, ArgError


@dataclass()
class Variable:
    value: str = ""
    description: str = ""


class Environment:
    """Class for working with module variables."""

    def __init__(self, config_path):
        self.__vars = dict()
        self.__load_config(config_path)

    def __str__(self):
        headers = [
            colorize_strings(
                "Name", fg=SGR.COLOR.FOREGROUND.CYAN, styles=[SGR.STYLES.BOLD]
            ),
            colorize_strings(
                "Value", fg=SGR.COLOR.FOREGROUND.CYAN, styles=[SGR.STYLES.BOLD]
            ),
            colorize_strings(
                "Description", fg=SGR.COLOR.FOREGROUND.CYAN, styles=[SGR.STYLES.BOLD]
            ),
        ]
        items = [
            [
                colorize_strings(name, fg=SGR.COLOR.FOREGROUND.YELLOW),
                colorize_strings(
                    "' '"
                    if var.value == " "
                    else var.value
                    if len(var.value) <= 30
                    else var.value[:30] + "...",
                    fg=SGR.COLOR.FOREGROUND.YELLOW,
                ),
                colorize_strings(
                    *var.description.split("\n"),
                    fg=SGR.COLOR.FOREGROUND.YELLOW,
                    sep="\n",
                ),
            ]
            for name, var in self.__vars.items()
        ]
        return tabulate(items, headers, tablefmt="fancy_grid")

    def __contains__(self, item):
        return item in self.__vars

    def __iter__(self):
        return iter(self.__vars.keys())

    @staticmethod
    def check_var(name: str, value: str) -> tuple[bool, str]:
        isvalid_var: bool = True
        error_message: str = ""
        return isvalid_var, error_message

    def get_var(self, name) -> Variable:
        """Getting a module-defined variable"""
        if name in self.__vars:
            return self.__vars[name]
        raise ArgError("No such variable")

    def set_var(self, name: str, value: str) -> None:
        """Setting a module-defined variable"""
        if name in self.__vars:
            isvalid, error_msg = self.check_var(name, value)
            if isvalid:
                self.__vars[name].value = value
            else:
                raise ArgError(error_msg)
        else:
            raise ArgError("No such variable")

    def __load_config(self, config_path):
        with open(config_path) as f:
            for name, params in load(f).items():
                self.__vars[name] = Variable(**params)


class BaseModule(metaclass=ABCMeta):
    def __init__(self):
        self.path = modules[self.__class__.__module__].__file__
        self.env = self.__load()
        self.proc: Popen | None = None

    @staticmethod
    def check_file(filename) -> tuple[bool, str]:
        """Check existence of file"""
        if isfile(filename):
            return True, ""
        return False, "Not a file"

    def kill_proc(self):
        if self.proc:
            self.proc.terminate()
            self.proc.kill()
            self.proc = None

    def command_exec(self, command, env=dict()) -> None:
        """Print output of executed shell command to console"""
        Printer.exec(f"Executing '{command}'")
        self.proc = Popen(
            command,
            stdin=stdin,
            shell=True,
            universal_newlines=True,
            env=dict(**environ, **env),
        )
        self.proc.wait()

    def __load(self) -> Environment:
        """Load config with module variables"""
        directory = dirname(self.path)
        config_path = join(directory, "config.json")
        if exists(config_path):
            env = Environment(config_path)
            return env
        raise ModuleError(f"No such file: {config_path}")

    @abstractmethod
    def run(self) -> None:
        """
        Required to be overridden in the child class.
        Function called by the user
        """
