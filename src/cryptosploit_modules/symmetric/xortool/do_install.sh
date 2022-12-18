pip install -r requirements.txt
git clone https://github.com/hellman/xortool.git
cd xortool
sed -i 's/`//g' pyproject.toml
poetry build
poetry install

