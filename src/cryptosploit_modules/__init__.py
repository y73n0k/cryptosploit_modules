from abc import ABCMeta, abstractmethod
from dataclasses import dataclass
from json import load
from os.path import dirname, join, exists, isfile
from subprocess import Popen, PIPE
from sys import modules
from tabulate import tabulate
from typing import Callable

from cryptosploit.exceptions import ModuleError, ArgError

# TODO: add Pprint class with colorful output

@dataclass()
class Variable:
    value: str = ""
    description: str = ""


def check_var(name: str, value: str):
    isvalid_var: bool = True
    error_message: str = ""
    return isvalid_var, error_message


class Environment:
    """
    Class for working with module variables.

    check_var should be overridden in the child class
    """

    check_var: Callable[[str, str], tuple[bool, str]] = check_var

    def __init__(self):
        self.__vars = dict()

    def __str__(self):
        headers = ["Name", "Value", "Description"]
        items = [
            [name, var.value, var.description] for name, var in self.__vars.items()
        ]
        return tabulate(items, headers, tablefmt="fancy_grid")

    def __contains__(self, item):
        return item in self.__vars

    def __iter__(self):
        return iter(self.__vars.keys())

    def get_var(self, name):
        if name in self.__vars:
            return self.__vars[name]
        raise ArgError("No such variable")

    def set_var(self, name: str, val: str):
        isvalid = True
        if name in self.__vars:
            if val:
                isvalid, error_msg = self.check_var(name, val)
            if isvalid:
                self.__vars[name].value = val
            else:
                raise ArgError(error_msg)
        else:
            raise ArgError("[! No such variable")

    def load_config(self, config_path):
        with open(config_path) as f:
            for name, params in load(f).items():
                self.__vars[name] = Variable(**params)


class BaseModule(metaclass=ABCMeta):
    def __init__(self):
        self.path = modules[self.__class__.__module__].__file__
        self.env = self.load()

    @staticmethod
    def check_file(filename):
        if isfile(filename):
            return True, ""
        return False, "[!] Not a file"

    @staticmethod
    def command_exec(command):
        print(f"[*] Executing '{command}'")
        proc = Popen(
            command,
            stderr=PIPE,
            shell=True,
            stdin=PIPE,
            stdout=PIPE,
            universal_newlines=True,
            text=True,
        )
        for line in iter(proc.stdout.readline, ""):
            print(line, end="")
        proc.stdout.close()
        for line in iter(proc.stderr.readline, ""):
            print(line, "\n")
        proc.stderr.close()

    def load(self) -> Environment:
        directory = dirname(self.path)
        config_path = join(directory, "config.json")
        if exists(config_path):
            env = Environment()
            env.load_config(config_path)
            return env
        raise ModuleError(f"No such file: {config_path}")

    @abstractmethod
    def run(self):
        """
        Required to be overridden in the child class
        """
