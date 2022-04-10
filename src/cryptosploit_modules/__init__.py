from abc import ABCMeta, abstractmethod
from dataclasses import dataclass
from os.path import dirname, join, exists
from sys import modules
from tabulate import tabulate
from json import load

from cryptosploit.exceptions import ModuleError, ArgError


@dataclass()
class Variable:
    value: str = ""
    description: str = ""


class Environment:
    def __init__(self):
        self.__vars = dict()

    def __str__(self):
        headers = ["Name", "Value", "Description"]
        items = [[name, var.value, var.description] for name, var in self.__vars.items()]
        return tabulate(items, headers, tablefmt="fancy_grid")

    def __contains__(self, item):
        return item in self.__vars

    def get_var(self, name):
        if name in self.__vars:
            return self.__vars[name]
        raise ArgError("No such variable")

    def set_var(self, name, val):
        if name in self.__vars:
            self.__vars[name].value = val
        else:
            raise ArgError("No such variable")

    def load_config(self, config_path):
        with open(config_path) as f:
            for name, params in load(f).items():
                self.__vars[name] = Variable(**params)


class BaseModule(metaclass=ABCMeta):
    def __init__(self):
        self.path = modules[self.__class__.__module__].__file__
        self.env = self.load()

    def load(self):
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
