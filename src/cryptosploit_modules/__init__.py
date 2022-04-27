from abc import ABCMeta, abstractmethod
from dataclasses import dataclass
from json import load
from os import environ
from os.path import dirname, join, exists, isfile
from subprocess import Popen, PIPE
from sys import modules
from tabulate import tabulate
from typing import Callable

from cryptosploit.cprint import Printer, colorize_strings, SGR
from cryptosploit.exceptions import ModuleError, ArgError


@dataclass()
class Variable:
    value: str = ""
    description: str = ""


def check_var(name: str, value: str) -> tuple[bool, str]:
    isvalid_var: bool = True
    error_message: str = ""
    return isvalid_var, error_message


class Environment:
    """Class for working with module variables."""

    check_var: Callable[[str, str], tuple[bool, str]] = check_var

    def __init__(self, config_path):
        self.__vars = dict()
        self.__load_config(config_path)

    def __str__(self):
        headers = [
            colorize_strings("Name", fg=SGR.COLOR.FOREGROUND.CYAN, styles=[SGR.STYLES.BOLD]),
            colorize_strings("Value", fg=SGR.COLOR.FOREGROUND.CYAN, styles=[SGR.STYLES.BOLD]),
            colorize_strings("Description", fg=SGR.COLOR.FOREGROUND.CYAN, styles=[SGR.STYLES.BOLD]),
        ]
        items = [
            [
                colorize_strings(name, fg=SGR.COLOR.FOREGROUND.YELLOW),
                colorize_strings(var.value if len(var.value) <= 30 else var.value[:30] + "...", fg=SGR.COLOR.FOREGROUND.YELLOW),
                colorize_strings(var.description, fg=SGR.COLOR.FOREGROUND.YELLOW)
            ] for name, var in self.__vars.items()
        ]
        return tabulate(items, headers, tablefmt="fancy_grid")

    def __contains__(self, item):
        return item in self.__vars

    def __iter__(self):
        return iter(self.__vars.keys())

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
            stderr=PIPE,
            shell=True,
            stdin=PIPE,
            stdout=PIPE,
            universal_newlines=True,
            text=True,
            env=dict(**environ, **env)
        )
        for line in iter(self.proc.stdout.readline, ""):
            print(line, end="")
        self.proc.stdout.close()
        for line in iter(self.proc.stderr.readline, ""):
            print(line, "\n")
        self.proc.stderr.close()

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
