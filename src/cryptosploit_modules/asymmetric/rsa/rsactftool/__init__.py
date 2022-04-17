from cryptosploit.exceptions import ModuleError
from cryptosploit_modules import BaseModule
from os.path import join, dirname
from pkg_resources import require, DistributionNotFound, VersionConflict

class RsaCtfToolModule(BaseModule):
    tool_path = join(dirname(__file__), "RsaCtfTool")

    def check_reqs(self):
        reqs_path = join(self.tool_path, "requirements.txt")
        with open(reqs_path) as f:
            pkgs = f.read()
        try:
            require(pkgs)
        except DistributionNotFound:
            print("[+] Install requirements for RsaCtfTool")
            self.command_exec(f"pip install -r {reqs_path}")
            self.command_exec(f"pip install -r {join(self.tool_path, 'optional-requirements.txt')}")
        except VersionConflict:
            print("[!] Cannot install requirements for RsaCtfTool because of version conflict")
            print("[!] We recommend you to install cryptosploit in venv")
    
    def run(self):
        self.check_reqs()
        self.command_exec(f'python {join(self.tool_path, "RsaCtfTool.py")} -h')    

module = RsaCtfToolModule()
