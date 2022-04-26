import os
from setuptools import setup
from setuptools.command.install import install

class PostInstall(install):
    def run(self):
        super().run()
        module_path = os.path.join(self.install_lib, "cryptosploit_modules")
        os.system(f"find {module_path} -name do_install.sh -print0 | xargs -0 -I [] sh -c 'cd $(dirname []) && source ./do_install.sh'")

setup(cmdclass={"install": PostInstall})
