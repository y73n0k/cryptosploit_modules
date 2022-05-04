from cryptosploit.cprint import Printer
from cryptosploit.exceptions import ArgError
from cryptosploit_modules import BaseModule

MORSE_CODE_DICT = {
    "A": ".-",
    "B": "-...",
    "C": "-.-.",
    "D": "-..",
    "E": ".",
    "F": "..-.",
    "G": "--.",
    "H": "....",
    "I": "..",
    "J": ".---",
    "K": "-.-",
    "L": ".-..",
    "M": "--",
    "N": "-.",
    "O": "---",
    "P": ".--.",
    "Q": "--.-",
    "R": ".-.",
    "S": "...",
    "T": "-",
    "U": "..-",
    "V": "...-",
    "W": ".--",
    "X": "-..-",
    "Y": "-.--",
    "Z": "--..",
    "1": ".----",
    "2": "..---",
    "3": "...--",
    "4": "....-",
    "5": ".....",
    "6": "-....",
    "7": "--...",
    "8": "---..",
    "9": "----.",
    "0": "-----",
    "." : ".-.-.-",
    "," : "--..--",
    ":" : "---...",
    "?" : "..--..",
    "'" : ".----.",
    "-" : "-....-",
    "/" : "-..-.",
    "@" : ".--.-.",
    "=" : "-...-",
    "(": "-.--.",
    ")": "-.--.-"
}


class Morse(BaseModule):
    def __init__(self):
        super().__init__()
        self.env.check_var = self.check_var

    @staticmethod
    def check_var(name, value):
        """Must return isvalid_variable: bool, error_msg: str"""
        match name:
            case "mode":
                if value in ("encode", "decode"):
                    return True, ""
                return False, "May be encode/decode"
            case _:
                return True, ""

    def encode_command(self, message):
        message = message.upper()
        ciphertext = ""
        for letter in message:
            if letter != " ":
                if letter in MORSE_CODE_DICT:
                    ciphertext += MORSE_CODE_DICT[letter] + " "
            else:
                ciphertext += " "
        Printer.positive("Encoded string:\n" + ciphertext)

    def decode_command(self, message):
        decipher = message
        Printer.positive("Decoded string:\n" + decipher)

    def run(self):
        mode = self.env.get_var("mode").value
        inp = self.env.get_var("input").value
        if mode and inp:
            func = getattr(self, self.env.get_var("mode").value + "_command")
            return func(inp)
        raise ArgError("All variables must be set")


module = Morse
