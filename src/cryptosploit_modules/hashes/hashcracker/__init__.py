from cryptosploit_modules import BaseModule
from cryptosploit.exceptions import ModuleError, ArgError
from subprocess import Popen, PIPE

class HashCracker(BaseModule):
    allowed_crackers = ("hashcat", "john")
    @staticmethod
    def command_exec(command):
        proc = Popen(command, stderr=PIPE, shell=True, stdin=PIPE, stdout=PIPE, universal_newlines=True, text=True)
        for line in iter(proc.stdout.readline, ""):
            print(line, end="")
        proc.stdout.close()
        for line in iter(proc.stderr.readline, ""):
            print(line, "\n")
            proc.stderr.close()
    
    
    def check_path(self):
        cracker = self.env.get_var("default_cracker").value
        if cracker in HashCracker.allowed_crackers:
            return True
        path = self.env.get_var("path_to_binary").value
        return any(i in path for i in HashCracker.allowed_crackers)


    def is_setted(*args):
        return all(i != "" for i in args)
    

    def help_command(self):
        return self.command_exec(self.env.get_var("path_to_binary").value or 
                                self.env.get_var("default_cracker").value)


    def crack_command(self):
        hash_type = self.env.get_var("hash_type").value
        input_hash = self.env.get_var("input_hash").value
        input_file = self.env.get_var("input_file").value
        
        if hash_type and any(input_hash, input_file):
            mode = self.env.get_var("mode").value
            path = self.env.get_var("path_to_binary").value
            if mode == "hashcat" or HashCracker.allowed_crackers[0] in path:
                # Hashcat
                ...
            else:
                # John the ripper
                ...


    def run(self):
        try:
            if self.check_path():
                func = getattr(self, self.env.get_var("mode").value + "_command")
                return func()
            else:
                raise ArgError("[!] No cracker or path_to_binary specified!\n \
                                Path must contain 'hashcat' or 'john'")
        except AttributeError:
            raise ModuleError("No such mode!")

module = HashCracker()
