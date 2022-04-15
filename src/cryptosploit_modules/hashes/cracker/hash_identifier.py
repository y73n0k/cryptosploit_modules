from name_that_hash import runner
from tabulate import tabulate


def identify_hash(filename):
    with open(filename) as f:
        hsh = f.read().split()[0]
        return runner.api_return_hashes_as_dict([hsh], {"popular_only": True})


def prettify_hash_info(hash_info):
    res = []
    headers = ["Name", "Hashcat", "John", "Extended", "Description"]
    for key in hash_info.keys():
        items = [[i[k] if i[k] is not None else "-" for k in i.keys()] for i in hash_info[key]]
        table = f"Input hash: {key}, possible types:\n"
        table += tabulate(items, headers, tablefmt="fancy_grid")
        res.append(table)
    return res
