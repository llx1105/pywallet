#!/usr/bin/env python
# -*- coding: utf-8 -*-
pywversion = "2.2"
secp256k1never_update = False
md5_pywallet = None
text_file = None
# jackjack's pywallet.py
# https://github.com/jackjack-jj/pywallet
# forked from Joric's pywallet.py
beta_version = ('a' in pywversion.split('-')[0]) or ('b' in pywversion.split('-')[0])

from lib.constants import *
from lib.dependency import *
from lib.ECDSA_constants import *

from model.AES import *
from model.crypter import *
from model.ECDSA import *
from model.hash import *
from model.key import *
from model.recover import *
from model.tx import *
from model.wallet import *
from interface import *

import thread
from optparse import OptionParser

pyw_filename = os.path.basename(__file__)
pyw_path = os.path.dirname(os.path.realpath(__file__))


# secp256k1
# python-ecdsa code (EC_KEY implementation)
# pywallet openssl private key implementation
# address handling code
# bitcointools wallet.dat handling code


def parse_CAddress(vds):
    d = {'ip': '0.0.0.0', 'port': 0, 'nTime': 0}
    try:
        d['nVersion'] = vds.read_int32()
        d['nTime'] = vds.read_uint32()
        d['nServices'] = vds.read_uint64()
        d['pchReserved'] = vds.read_bytes(12)
        d['ip'] = socket.inet_ntoa(vds.read_bytes(4))
        d['port'] = vds.read_uint16()
    except:
        pass
    return d


def deserialize_CAddress(d):
    return d['ip'] + ":" + str(d['port'])


def parse_BlockLocator(vds):
    d = {'hashes': []}
    nHashes = vds.read_compact_size()
    for i in xrange(nHashes):
        d['hashes'].append(vds.read_bytes(32))
        return d


def deserialize_BlockLocator(d):
    result = "Block Locator top: " + d['hashes'][0][::-1].encode('hex_codec')
    return result


def parse_setting(setting, vds):
    if setting[0] == "f":  # flag (boolean) settings
        return str(vds.read_boolean())
    elif setting[0:4] == "addr":  # CAddress
        d = parse_CAddress(vds)
        return deserialize_CAddress(d)
    elif setting == "nTransactionFee":
        return vds.read_int64()
    elif setting == "nLimitProcessors":
        return vds.read_int32()
    return 'unknown setting'


def check_postkeys(key, postkeys):
    for i in postkeys:
        if key[:len(i)] == i:
            return True
    return False


def one_element_in(a, string):
    for i in a:
        if i in string:
            return True
    return False


def first_read(device, size, prekeys, inc=10000):
    t0 = ts() - 1
    try:
        fd = os.open(device, os.O_RDONLY)
    except:
        print("Can't open %s, check the path or try as root" % device)
        exit(0)
    prekey = prekeys[0]
    data = ""
    i = 0
    data = os.read(fd, i)
    before_contained_key = False
    contains_key = False
    ranges = []

    while i < int(size):
        if i % (10 * Mio) > 0 and i % (10 * Mio) <= inc:
            print("\n%.2f/%.2f Go" % (i / 1e9, size / 1e9))
            t = ts()
            speed = i / (t - t0)
            ETAts = size / speed + t0
            d = datetime.fromtimestamp(ETAts)
            print(d.strftime("   ETA: %H:%M:%S"))

        try:
            data = os.read(fd, inc)
        except Exception as exc:
            os.lseek(fd, inc, os.SEEK_CUR)
            print str(exc)
            i += inc
            continue

        contains_key = one_element_in(prekeys, data)

        if not before_contained_key and contains_key:
            ranges.append(i)

        if before_contained_key and not contains_key:
            ranges.append(i)

        before_contained_key = contains_key

        i += inc

    os.close(fd)
    return ranges


def md5_file(nf):
    try:
        fichier = file(nf, 'r').read()
        return md5_2(fichier)
    except:
        return 'zz'


def bool_to_int(b):
    if b:
        return 1
    return 0


# wallet.dat reader / writer
def importprivkey(db, sec, label, reserve, keyishex, verbose=True, addrv=addrtype):
    global addrtype
    if options.coin_type is None:
        options.coin_type = 'Bitcoin'
    if len(get_keys(aversions, options.coin_type.capitalize())) is 0:
        print("please input an valid coin type e.g. bitcoin/litecoin")
        exit(0)
    else:
        addrv = get_keys(aversions, options.coin_type.capitalize())[-1]
    if keyishex is None:
        pkey = regenerate_key(sec)
        compressed = is_compressed(sec)
    elif len(sec) == 64:
        pkey = EC_KEY(str_to_long(sec.decode('hex')))
        compressed = False
    elif len(sec) == 66:
        pkey = EC_KEY(str_to_long(sec[:-2].decode('hex')))
        compressed = True
    else:
        print("Hexadecimal private keys must be 64 or 66 characters long (specified one is " + str(
            len(sec)) + " characters long)")
        return False

    if not pkey:
        return False

    secret = GetSecret(pkey)
    private_key = GetPrivKey(pkey, compressed)
    public_key = GetPubKey(pkey, compressed)
    addr = public_key_to_bc_address(public_key, addrv)

    if verbose:

        str_info = "\nAddress (%s): %s\n" % (aversions[addrv], addr) \
                   + "Privkey (%s): %s\n" % (aversions[addrv], SecretToASecret(secret, compressed, addrv)) \
                   + "Hexprivkey: %s\n" % (secret.encode('hex')) \
                   + "Hash160: %s\n" % (bc_address_to_hash_160(addr).encode('hex'))
        if not compressed:
            str_info += "Pubkey: 04%.64x%.64x\n" % (pkey.pubkey.point.x(), pkey.pubkey.point.y())
        else:
            str_info += "Pubkey: 0%d%.64x\n" % (2 + (pkey.pubkey.point.y() & 1), pkey.pubkey.point.x())
        if int(secret.encode('hex'), 16) > _r:
            str_info += 'Beware, 0x%s is equivalent to 0x%.33x</b>\n' % (
                secret.encode('hex'), int(secret.encode('hex'), 16) - _r)

        if text_file is not None:
            text_file.write(str_info)

        print str_info

    global crypter, passphrase, json_db
    crypted = False
    if 'mkey' in json_db.keys() and 'salt' in json_db['mkey']:
        crypted = True
    if crypted:
        if passphrase:
            cry_master = json_db['mkey']['encrypted_key'].decode('hex')
            cry_salt = json_db['mkey']['salt'].decode('hex')
            cry_rounds = json_db['mkey']['nDerivationIterations']
            cry_method = json_db['mkey']['nDerivationMethod']

            crypter.SetKeyFromPassphrase(passphrase, cry_salt, cry_rounds, cry_method)
            #			if verbose:
            #				print "Import with", passphrase, "", cry_master.encode('hex'), "", cry_salt.encode('hex')
            masterkey = crypter.Decrypt(cry_master)
            crypter.SetKey(masterkey)
            crypter.SetIV(Hash(public_key))
            e = crypter.Encrypt(secret)
            ck_epk = e

            update_wallet(db, 'ckey', {'public_key': public_key, 'encrypted_private_key': ck_epk})
    else:
        update_wallet(db, 'key', {'public_key': public_key, 'private_key': private_key})

    if not reserve:
        update_wallet(db, 'name', {'hash': addr, 'name': label})

    return True


def balance(site, address):
    page = urllib.urlopen("%s%s" % (site, address))
    return page.read()


def read_jsonfile(filename):
    filin = open(filename, 'r')
    txdump = filin.read()
    filin.close()
    return json.loads(txdump)


def write_jsonfile(filename, array):
    filout = open(filename, 'w')
    filout.write(json.dumps(array, sort_keys=True, indent=0))
    filout.close()


def read_table(table, beg, end):
    rows = table.split(beg)
    for i in range(len(rows)):
        rows[i] = rows[i].split(end)[0]
    return rows


def read_blockexplorer_table(table):
    cell = []
    rows = read_table(table, '<tr>', '</tr>')
    for i in range(len(rows)):
        cell.append(read_table(rows[i], '<td>', '</td>'))
        del cell[i][0]
    del cell[0]
    del cell[0]
    return cell


def inverse_str(string):
    ret = ""
    for i in range(len(string) / 2):
        ret += string[len(string) - 2 - 2 * i];
        ret += string[len(string) - 2 - 2 * i + 1];
    return ret


if __name__ == '__main__':

    parser = OptionParser(usage="%prog [options]", version="%prog 1.1")

    parser.add_option("--passphrase", dest="passphrase",
                      help="passphrase for the encrypted wallet")

    parser.add_option("--dumpwallet", dest="dump", action="store_true",
                      help="dump wallet in json format")

    parser.add_option("--dumpwithbalance", dest="dumpbalance", action="store_true",
                      help="includes balance of each address in the json dump, takes about 2 minutes per 100 addresses")

    parser.add_option("--importprivkey", dest="key",
                      help="import private key from vanitygen")

    parser.add_option("--importhex", dest="keyishex", action="store_true",
                      help="KEY is in hexadecimal format")

    parser.add_option("--datadir", dest="datadir",
                      help="wallet directory (defaults to bitcoin default)")

    parser.add_option("--wallet", dest="walletfile",
                      help="wallet filename (defaults to wallet.dat)",
                      default="wallet.dat")

    parser.add_option("--label", dest="label",
                      help="label shown in the adress book (defaults to '')",
                      default="")

    parser.add_option("--testnet", dest="testnet", action="store_true",
                      help="use testnet subdirectory and address type")

    parser.add_option("--namecoin", dest="namecoin", action="store_true",
                      help="use namecoin address type")

    parser.add_option("--otherversion", dest="otherversion",
                      help="use other network address type, whose version is OTHERVERSION")

    parser.add_option("--info", dest="keyinfo", action="store_true",
                      help="display pubkey, privkey (both depending on the network) and hexkey")

    parser.add_option("--reserve", dest="reserve", action="store_true",
                      help="import as a reserve key, i.e. it won't show in the adress book")

    parser.add_option("--multidelete", dest="multidelete",
                      help="deletes data in your wallet, according to the file provided")

    parser.add_option("--balance", dest="key_balance",
                      help="prints balance of KEY_BALANCE")

    parser.add_option("--web", dest="web", action="store_true",
                      help="run pywallet web interface")

    parser.add_option("--port", dest="port",
                      help="port of web interface (defaults to 8989)")

    parser.add_option("--recover", dest="recover", action="store_true",
                      help="recover your deleted keys, use with recov_size and recov_device")

    parser.add_option("--recov_device", dest="recov_device",
                      help="device to read (e.g. /dev/sda1 or E: or a file)")

    parser.add_option("--recov_size", dest="recov_size",
                      help="number of bytes to read (e.g. 20Mo or 50Gio)")

    parser.add_option("--write_text", dest="write_text", action="store_true",
                      help="write keys info")

    parser.add_option("--recov_outputdir", dest="recov_outputdir",
                      help="output directory where the recovered wallet will be put")

    parser.add_option("--coin_type", dest="coin_type",
                      help="type of coin (e.g. bitcoin or litecoin)")

    parser.add_option("--clone_watchonly_from", dest="clone_watchonly_from",
                      help="path of the original wallet")

    parser.add_option("--clone_watchonly_to", dest="clone_watchonly_to",
                      help="path of the resulting watch-only wallet")

    parser.add_option("--dont_check_walletversion", dest="dcv", action="store_true",
                      help="don't check if wallet version > %d before running (WARNING: this may break your wallet, be sure you know what you do)" % max_version)

    parser.add_option("--wait", dest="nseconds",
                      help="wait NSECONDS seconds before launch")

    #	parser.add_option("--forcerun", dest="forcerun",
    #		action="store_true",
    #		help="run even if pywallet detects bitcoin is running")

    (options, args) = parser.parse_args()

    #	a=Popen("ps xa | grep ' bitcoin'", shell=True, bufsize=-1, stdout=PIPE).stdout
    #	aread=a.read()
    #	nl = aread.count("\n")
    #	a.close()
    #	if nl > 2:
    #		print('Bitcoin seems to be running: \n"%s"'%(aread))
    #		if options.forcerun is None:
    #			exit(0)


    """
    function:recover wallet
    parameters:
        recov_size: the size of the device
        recov_device: recover file
        recov_outputdir: the output path
    """
    if options.recover:
        if options.recov_size is None or options.recov_device is None or options.recov_outputdir is None:
            print("You must provide the device, the number of bytes to read and the output directory")
            exit(0)
        if options.coin_type is None:
            options.coin_type = 'Bitcoin'
        if len(get_keys(aversions, options.coin_type.capitalize())) is 0:
            print("please input an valid coin type e.g. bitcoin/litecoin")
            exit(0)
        device = options.recov_device
        if len(device) in [2, 3] and device[1] == ':':
            device = "\\\\.\\" + device
        size = read_device_size(options.recov_size)
        passphraseRecov = ''
        while passphraseRecov == '':
            passphraseRecov = raw_input(
                "Enter the passphrase for the wallet that will contain all the recovered keys: ")
        passphrase = passphraseRecov

        passes = []
        p = ' '
        print '\nEnter the possible passphrases used in your deleted wallets.'
        print "Don't forget that more passphrases = more time to test the possibilities."
        print 'Write one passphrase per line and end with an empty line.'
        while p != '':
            p = raw_input("Possible passphrase: ")
            if p != '':
                passes.append(p)

        print "\nStarting recovery."
        recoveredKeys = recov(device, passes, size, 10240, options.recov_outputdir)
        recoveredKeys = list(set(recoveredKeys))
        #		print recoveredKeys[0:5]


        db_env = create_env(options.recov_outputdir)
        recov_wallet_name = "recovered_wallet_%s.dat" % ts()

        create_new_wallet(db_env, recov_wallet_name, 32500)

        if passphraseRecov != "I don't want to put a password on the recovered wallet and I know what can be the consequences.":
            db = open_wallet(db_env, recov_wallet_name, True)

            # 随机产生n个字节的字符串，可以作为随机加密key使用
            NPP_salt = os.urandom(8)
            NPP_rounds = int(50000 + random.random() * 20000)
            NPP_method = 0
            NPP_MK = os.urandom(32)
            crypter.SetKeyFromPassphrase(passphraseRecov, NPP_salt, NPP_rounds, NPP_method)
            NPP_EMK = crypter.Encrypt(NPP_MK)
            update_wallet(db, 'mkey', {
                "encrypted_key": NPP_EMK,
                'nDerivationIterations': NPP_rounds,
                'nDerivationMethod': NPP_method,
                'nID': 1,
                'otherParams': ''.decode('hex'),
                "salt": NPP_salt
            })
            db.close()

        read_wallet(json_db, db_env, recov_wallet_name, True, True, "", False)

        db = open_wallet(db_env, recov_wallet_name, True)

        if options.write_text is True:
            txt_file_name = '/recovery_information_%d.txt' % ts()
            text_file = file(options.recov_outputdir + txt_file_name, 'a+')

        print "\n\nImporting:"
        for i, sec in enumerate(recoveredKeys):
            sec = sec.encode('hex')
            print("\nImporting key %4d/%d:" % (i + 1, len(recoveredKeys)))
            text_file.write("\nkey %4d/%d:" % (i + 1, len(recoveredKeys)))
            importprivkey(db, sec, "recovered: %s" % sec, None, True)
            print ("\nCompressed key and address:")
            text_file.write("Compressed key and address:\n")
            importprivkey(db, sec + '01', "recovered: %s" % sec, None, True)
        db.close()
        text_file.close()

        print("\nThe new wallet %s/%s contains the %d recovered key%s" % (
            options.recov_outputdir, recov_wallet_name, len(recoveredKeys), iais(len(recoveredKeys))))

        if options.write_text is True:

            print("\nThe new text file %s%s contains the %d recovered key%s" % (
                options.recov_outputdir, txt_file_name, len(recoveredKeys), iais(len(recoveredKeys))))

        exit(0)

    if 'bsddb' in missing_dep:
        print("pywallet needs 'bsddb' package to run, please install it")
        exit(0)

    if 'twisted' in missing_dep and options.web is not None:
        print("'twisted' package is not installed, pywallet web interface can't be launched")
        exit(0)

    if 'ecdsa' in missing_dep:
        print("'ecdsa' package is not installed, pywallet won't be able to sign/verify messages")

    if 'twisted' not in missing_dep:
        VIEWS = {
            'DumpWallet': WIDumpWallet(),
            'MergeWallets': WIMergeWallets(),
            'Import': WIImport(),
            'ImportTx': WIImportTx(),
            'DumpTx': WIDumpTx(),
            'Info': WIInfo(),
            'Delete': WIDelete(),
            'Balance': WIBalance(),
            'ChangePP': WIChangePP(),
            'Others': WIOthers(),
            'LoadBalances': WICTTest(),
            'CTTest': WICTTest(),
            'ListTransactions': WICTListTx(),
            'CreateTransaction': WICT(),
            'CT': WICT(),
            'quit': WIQuit()

        }

    if options.nseconds:
        time.sleep(int(options.nseconds))

    if options.passphrase:
        passphrase = options.passphrase

    if options.clone_watchonly_from is not None and options.clone_watchonly_to:
        clone_wallet(options.clone_watchonly_from, options.clone_watchonly_to)
        exit(0)

    if options.dcv is not None:
        max_version = 10 ** 9

    if options.datadir is not None:
        wallet_dir = options.datadir

    if options.walletfile is not None:
        wallet_name = options.walletfile

    if 'twisted' not in missing_dep and options.web is not None:
        md5_pywallet = md5_file(pyw_path + "/" + pyw_filename)
        thread.start_new_thread(retrieve_last_pywallet_md5, ())

        webport = 8989
        if options.port is not None:
            webport = int(options.port)
        root = WIRoot()
        for viewName, className in VIEWS.items():
            root.putChild(viewName, className)
        log.startLogging(sys.stdout)
        log.msg('Starting server: %s' % str(datetime.now()))
        server = server.Site(root)
        reactor.listenTCP(webport, server)
        reactor.run()
        exit(0)

    if options.key_balance is not None:
        print(balance(balance_site, options.key_balance))
        exit(0)

    if options.dump is None and options.key is None and options.multidelete is None:
        print "A mandatory option is missing\n"
        parser.print_help()
        exit(0)

    if options.namecoin or options.otherversion is not None:
        if options.datadir is None and options.keyinfo is None:
            print("You must provide your wallet directory")
            exit(0)
        else:
            if options.namecoin:
                addrtype = 52
            else:
                addrtype = int(options.otherversion)
    '''
    Create a Bitcoin address from scratch
    input: ./pywallet.py --info --importhex --importprivkey 1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef
    output:
    Address (Bitcoin): 18FRQvrw9N5zhUgCR15G6ZJavPMbEDkwVY
    Privkey (Bitcoin): 5HxJb9hZNXEEk9SAM3J7gXBK6zgkkLW5dpx2WDdBZub8HUXTaZF
    Hexprivkey:   1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdeb
    Hash160:      4f831520dadeb082d98af6caeac8515a321bd46e
    '''
    ## options.key input scratch
    ## keyishex default true
    if options.keyinfo is not None:
        if not keyinfo(options.key, options.keyishex, options.coin_type):
            print "Bad private key"
        exit(0)

    db_dir = determine_db_dir()

    if options.testnet:
        db_dir += "/testnet3"
        addrtype = 111

    db_env = create_env(db_dir)

    if options.multidelete is not None:
        filename = options.multidelete
        filin = open(filename, 'r')
        content = filin.read().split('\n')
        filin.close()
        typedel = content[0]
        kd = filter(bool, content[1:])
        try:
            r = delete_from_wallet(db_env, determine_db_name(), typedel, kd)
            print '%d element%s deleted' % (r, 's' * (int(r > 1)))
        except:
            print "Error: do not try to delete a non-existing transaction."
            exit(1)
        exit(0)

    read_wallet(json_db, db_env, determine_db_name(), True, True, "", options.dumpbalance is not None)

    if json_db.get('minversion') > max_version:
        print "Version mismatch (must be <= %d)" % max_version
    # exit(1)

    if options.dump:
        print json.dumps(json_db, sort_keys=True, indent=4)
    elif options.key:
        if json_db['version'] > max_version:
            print "Version mismatch (must be <= %d)" % max_version
        elif (options.keyishex is None and options.key in private_keys) or (
                        options.keyishex is not None and options.key in private_hex_keys):
            print "Already exists"
        else:
            db = open_wallet(db_env, determine_db_name(), writable=True)

            if importprivkey(db, options.key, options.label, options.reserve, options.keyishex):
                print "Imported successfully"
            else:
                print "Bad private key"

            db.close()
