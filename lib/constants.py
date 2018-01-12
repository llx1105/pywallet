max_version = 81000
addrtype = 0
json_db = {}
private_keys = []
private_hex_keys = []
passphrase = ""
global_merging_message = ["", ""]
missing_dep = []
addr_to_keys = {}
balance_site = 'https://blockchain.info/q/addressbalance/'
aversions = {};
for i in range(256):
    aversions[i] = "version %d" % i;
aversions[0] = 'Bitcoin';
aversions[48] = 'Litecoin';
aversions[52] = 'Namecoin';
aversions[111] = 'Testnet';
ct_txin = []
ct_txout = []
md5_last_pywallet = [False, ""]

empty_txin = {'hash': '', 'index': '', 'sig': '##', 'pubkey': '', 'oldscript': '', 'addr': ''}
empty_txout = {'amount': '', 'script': ''}

wallet_dir = ""
wallet_name = ""

ko = 1e3
kio = 1024
Mo = 1e6
Mio = 1024 ** 2
Go = 1e9
Gio = 1024 ** 3
To = 1e12
Tio = 1024 ** 4
prekeys = ["308201130201010420".decode('hex'), "308201120201010420".decode('hex')]
postkeys = ["a081a530".decode('hex'), "81a530".decode('hex')]

