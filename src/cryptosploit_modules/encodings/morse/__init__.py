from os.path import isfile

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
    ".": ".-.-.-",
    ",": "--..--",
    ":": "---...",
    "?": "..--..",
    "'": ".----.",
    "-": "-....-",
    "/": "-..-.",
    "@": ".--.-.",
    "=": "-...-",
    "(": "-.--.",
    ")": "-.--.-",
}

MORSE_DECODE_DICT = {value: key for key, value in MORSE_CODE_DICT.items()}


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

    def encode_command(self, message, letter_delimiter, word_delimiter):
        message = message.upper()
        encoded = ""
        for letter in message:
            if letter not in (" ", "\n"):
                if letter in MORSE_CODE_DICT:
                    encoded += MORSE_CODE_DICT[letter] + letter_delimiter
                else:
                    raise ArgError(f"Letter '{letter}' can't be parsed")
            else:
                encoded += word_delimiter
        Printer.positive("Encoded string:\n" + encoded)

    def decode_command(self, message, letter_delimiter, word_delimiter):
        words = filter(lambda a: a, message.split(word_delimiter))
        decoded = ""
        for word in words:
            morse_codes = filter(lambda a: a, word.split(letter_delimiter))
            for morse_code in morse_codes:
                if morse_code in MORSE_DECODE_DICT:
                    decoded += MORSE_DECODE_DICT[morse_code]
                else:
                    raise ArgError(f"Morse code '{morse_code}' can't be parsed")
            decoded += " "
        Printer.positive("Decoded string:\n" + decoded)

    def run(self):
        inp = self.env.get_var("input").value
        if isfile(inp):
            with open(inp) as f:
                inp = f.read()
        letter_delimiter = self.env.get_var("letter_delimiter").value
        word_delimiter = self.env.get_var("word_delimiter").value
        if inp:
            if (
                letter_delimiter.startswith('"')
                and letter_delimiter.endswith('"')
                and len(letter_delimiter) > 1
            ):
                letter_delimiter = letter_delimiter[1:-1]
            if (
                word_delimiter.startswith('"')
                and word_delimiter.endswith('"')
                and len(word_delimiter) > 1
            ):
                word_delimiter = word_delimiter[1:-1]
            if letter_delimiter:
                func = getattr(self, self.env.get_var("mode").value + "_command")
                return func(inp, letter_delimiter, word_delimiter)
            raise ArgError("Letter delimiter must be not empty")
        raise ArgError("Input must be set")


module = Morse
