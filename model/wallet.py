#!/usr/bin/env python
# -*- coding: utf-8 -*-
from lib.constants import *
from lib.dependency import *
from lib.ECDSA_constants import *
from key import *
from BCDstream import *
from crypter import *


def open_wallet(db_env, walletfile, writable=False):
    db = DB(db_env)
    if writable:
        DB_TYPEOPEN = DB_CREATE
    else:
        DB_TYPEOPEN = DB_RDONLY
    flags = DB_THREAD | DB_TYPEOPEN
    try:
        r = db.open(walletfile, "main", DB_BTREE, flags)
    except DBError:
        r = True

    if r is not None:
        logging.error("Couldn't open wallet.dat/main. Try quitting Bitcoin and running this again.")
        sys.exit(1)

    return db


def inversetxid(txid):
    if len(txid) is not 64:
        print("Bad txid")
        return "CORRUPTEDTXID:" + txid
    # exit(0)
    new_txid = ""
    for i in range(32):
        new_txid += txid[62 - 2 * i];
        new_txid += txid[62 - 2 * i + 1];
    return new_txid


def parse_wallet(db, item_callback):
    kds = BCDataStream()
    vds = BCDataStream()

    def parse_TxIn(vds):
        d = {}
        d['prevout_hash'] = vds.read_bytes(32).encode('hex')
        d['prevout_n'] = vds.read_uint32()
        d['scriptSig'] = vds.read_bytes(vds.read_compact_size()).encode('hex')
        d['sequence'] = vds.read_uint32()
        return d

    def parse_TxOut(vds):
        d = {}
        d['value'] = vds.read_int64() / 1e8
        d['scriptPubKey'] = vds.read_bytes(vds.read_compact_size()).encode('hex')
        return d

    for (key, value) in db.items():
        d = {}

        kds.clear();
        kds.write(key)
        vds.clear();
        vds.write(value)

        type = kds.read_string()

        d["__key__"] = key
        d["__value__"] = value
        d["__type__"] = type

        try:
            if type == "tx":
                d["tx_id"] = inversetxid(kds.read_bytes(32).encode('hex_codec'))
                start = vds.read_cursor
                d['version'] = vds.read_int32()
                n_vin = vds.read_compact_size()
                d['txIn'] = []
                for i in xrange(n_vin):
                    d['txIn'].append(parse_TxIn(vds))
                n_vout = vds.read_compact_size()
                d['txOut'] = []
                for i in xrange(n_vout):
                    d['txOut'].append(parse_TxOut(vds))
                d['lockTime'] = vds.read_uint32()
                d['tx'] = vds.input[start:vds.read_cursor].encode('hex_codec')
                d['txv'] = value.encode('hex_codec')
                d['txk'] = key.encode('hex_codec')
            elif type == "name":
                d['hash'] = kds.read_string()
                d['name'] = vds.read_string()
            elif type == "version":
                d['version'] = vds.read_uint32()
            elif type == "minversion":
                d['minversion'] = vds.read_uint32()
            elif type == "setting":
                d['setting'] = kds.read_string()
                d['value'] = parse_setting(d['setting'], vds)
            elif type == "key":
                d['public_key'] = kds.read_bytes(kds.read_compact_size())
                d['private_key'] = vds.read_bytes(vds.read_compact_size())
            elif type == "wkey":
                d['public_key'] = kds.read_bytes(kds.read_compact_size())
                d['private_key'] = vds.read_bytes(vds.read_compact_size())
                d['created'] = vds.read_int64()
                d['expires'] = vds.read_int64()
                d['comment'] = vds.read_string()
            elif type == "defaultkey":
                d['key'] = vds.read_bytes(vds.read_compact_size())
            elif type == "pool":
                d['n'] = kds.read_int64()
                d['nVersion'] = vds.read_int32()
                d['nTime'] = vds.read_int64()
                d['public_key'] = vds.read_bytes(vds.read_compact_size())
            elif type == "acc":
                d['account'] = kds.read_string()
                d['nVersion'] = vds.read_int32()
                d['public_key'] = vds.read_bytes(vds.read_compact_size())
            elif type == "acentry":
                d['account'] = kds.read_string()
                d['n'] = kds.read_uint64()
                d['nVersion'] = vds.read_int32()
                d['nCreditDebit'] = vds.read_int64()
                d['nTime'] = vds.read_int64()
                d['otherAccount'] = vds.read_string()
                d['comment'] = vds.read_string()
            elif type == "bestblock":
                d['nVersion'] = vds.read_int32()
                d.update(parse_BlockLocator(vds))
            elif type == "ckey":
                d['public_key'] = kds.read_bytes(kds.read_compact_size())
                d['encrypted_private_key'] = vds.read_bytes(vds.read_compact_size())
            elif type == "mkey":
                d['nID'] = kds.read_uint32()
                d['encrypted_key'] = vds.read_string()
                d['salt'] = vds.read_string()
                d['nDerivationMethod'] = vds.read_uint32()
                d['nDerivationIterations'] = vds.read_uint32()
                d['otherParams'] = vds.read_string()

            item_callback(type, d)

        except Exception, e:
            traceback.print_exc()
            print("ERROR parsing wallet.dat, type %s" % type)
            print("key data: %s" % key)
            print("key data in hex: %s" % key.encode('hex_codec'))
            print("value data in hex: %s" % value.encode('hex_codec'))
            sys.exit(1)


def delete_from_wallet(db_env, walletfile, typedel, kd):
    db = open_wallet(db_env, walletfile, True)
    kds = BCDataStream()
    vds = BCDataStream()

    deleted_items = 0

    if not isinstance(kd, list):
        kd = [kd]

    if typedel == 'tx' and kd != ['all']:
        for keydel in kd:
            db.delete('\x02\x74\x78' + keydel.decode('hex')[::-1])
            deleted_items += 1

    else:
        for i, keydel in enumerate(kd):
            for (key, value) in db.items():
                kds.clear();
                kds.write(key)
                vds.clear();
                vds.write(value)
                type = kds.read_string()

                if typedel == "tx" and type == "tx":
                    db.delete(key)
                    deleted_items += 1
                elif typedel == "key":
                    if type == "key" or type == "ckey":
                        if keydel == public_key_to_bc_address(kds.read_bytes(kds.read_compact_size())):
                            db.delete(key)
                            deleted_items += 1
                    elif type == "pool":
                        vds.read_int32()
                        vds.read_int64()
                        if keydel == public_key_to_bc_address(vds.read_bytes(vds.read_compact_size())):
                            db.delete(key)
                            deleted_items += 1
                    elif type == "name":
                        if keydel == kds.read_string():
                            db.delete(key)
                            deleted_items += 1

    db.close()
    return deleted_items


def merge_keys_lists(la, lb):
    lr = {}
    llr = []
    for k in la:
        lr[k[0]] = k[1]

    for k in lb:
        if k[0] in lr.keys():
            lr[k[0]] = lr[k[0]] + " / " + k[1]
        else:
            lr[k[0]] = k[1]

    for k, j in lr.items():
        llr.append([k, j])

    return llr


def merge_wallets(wadir, wa, wbdir, wb, wrdir, wr, passphrase_a, passphrase_b, passphrase_r):
    global passphrase
    passphrase_LAST = passphrase

    # Read Wallet 1
    passphrase = passphrase_a
    dba_env = create_env(wadir)
    crypted_a = read_wallet(json_db, dba_env, wa, True, True, "", None)['crypted']

    list_keys_a = []
    for i in json_db['keys']:
        try:
            label = i['label']
        except:
            label = "#Reserve"
        try:
            list_keys_a.append([i['secret'], label])
        except:
            pass

    if len(list_keys_a) == 0:
        return [False, "Something went wrong with the first wallet."]

    # Read Wallet 2
    passphrase = passphrase_b
    dbb_env = create_env(wbdir)
    crypted_b = read_wallet(json_db, dbb_env, wb, True, True, "", None)['crypted']

    list_keys_b = []
    for i in json_db['keys']:
        try:
            label = i['label']
        except:
            label = "#Reserve"
        try:
            list_keys_b.append([i['secret'], label])
        except:
            pass
    if len(list_keys_b) == 0:
        return [False, "Something went wrong with the second wallet."]

    m = merge_keys_lists(list_keys_a, list_keys_b)

    # Create new wallet
    dbr_env = create_env(wrdir)
    create_new_wallet(dbr_env, wr, 80100)

    dbr = open_wallet(dbr_env, wr, True)
    update_wallet(dbr, 'minversion', {'minversion': 60000})

    if len(passphrase_r) > 0:
        NPP_salt = os.urandom(8)
        NPP_rounds = int(50000 + random.random() * 20000)
        NPP_method = 0
        NPP_MK = os.urandom(32)

        crypter.SetKeyFromPassphrase(passphrase_r, NPP_salt, NPP_rounds, NPP_method)
        NPP_EMK = crypter.Encrypt(NPP_MK)

        update_wallet(dbr, 'mkey', {
            "encrypted_key": NPP_EMK,
            'nDerivationIterations': NPP_rounds,
            'nDerivationMethod': NPP_method,
            'nID': 1,
            'otherParams': ''.decode('hex'),
            "salt": NPP_salt
        })

    dbr.close()

    t = '\n'.join(map(lambda x: ';'.join(x), m))
    passphrase = passphrase_r

    global global_merging_message

    global_merging_message = ["Merging...", "Merging..."]
    thread.start_new_thread(import_csv_keys, ("\x00" + t, wrdir, wr,))
    t = ""

    passphrase = passphrase_LAST

    return [True]


def random_string(l, alph="0123456789abcdef"):
    r = ""
    la = len(alph)
    for i in range(l):
        r += alph[int(la * (random.random()))]
    return r


def update_wallet(db, types, datas, paramsAreLists=False):
    """Write a single item to the wallet.
	db must be open with writable=True.
	type and data are the type code and data dictionary as parse_wallet would
	give to item_callback.
	data's __key__, __value__ and __type__ are ignored; only the primary data
	fields are used.
	"""

    if not paramsAreLists:
        types = [types]
        datas = [datas]

    if len(types) != len(datas):
        raise Exception("UpdateWallet: sizes are different")

    for it, type in enumerate(types):
        data = datas[it]

        d = data
        kds = BCDataStream()
        vds = BCDataStream()

        # Write the type code to the key
        kds.write_string(type)
        vds.write("")  # Ensure there is something

        try:
            if type == "tx":
                #			raise NotImplementedError("Writing items of type 'tx'")
                kds.write(d['txi'][6:].decode('hex_codec'))
                vds.write(d['txv'].decode('hex_codec'))
            elif type == "name":
                kds.write_string(d['hash'])
                vds.write_string(d['name'])
            elif type == "version":
                vds.write_uint32(d['version'])
            elif type == "minversion":
                vds.write_uint32(d['minversion'])
            elif type == "setting":
                raise NotImplementedError("Writing items of type 'setting'")
                kds.write_string(d['setting'])
            # d['value'] = parse_setting(d['setting'], vds)
            elif type == "key":
                kds.write_string(d['public_key'])
                vds.write_string(d['private_key'])
            elif type == "wkey":
                kds.write_string(d['public_key'])
                vds.write_string(d['private_key'])
                vds.write_int64(d['created'])
                vds.write_int64(d['expires'])
                vds.write_string(d['comment'])
            elif type == "defaultkey":
                vds.write_string(d['key'])
            elif type == "pool":
                kds.write_int64(d['n'])
                vds.write_int32(d['nVersion'])
                vds.write_int64(d['nTime'])
                vds.write_string(d['public_key'])
            elif type == "acc":
                kds.write_string(d['account'])
                vds.write_int32(d['nVersion'])
                vds.write_string(d['public_key'])
            elif type == "acentry":
                kds.write_string(d['account'])
                kds.write_uint64(d['n'])
                vds.write_int32(d['nVersion'])
                vds.write_int64(d['nCreditDebit'])
                vds.write_int64(d['nTime'])
                vds.write_string(d['otherAccount'])
                vds.write_string(d['comment'])
            elif type == "bestblock":
                vds.write_int32(d['nVersion'])
                vds.write_compact_size(len(d['hashes']))
                for h in d['hashes']:
                    vds.write(h)
            elif type == "ckey":
                kds.write_string(d['public_key'])
                vds.write_string(d['encrypted_private_key'])
            elif type == "mkey":
                kds.write_uint32(d['nID'])
                vds.write_string(d['encrypted_key'])
                vds.write_string(d['salt'])
                vds.write_uint32(d['nDerivationMethod'])
                vds.write_uint32(d['nDerivationIterations'])
                vds.write_string(d['otherParams'])

            else:
                print "Unknown key type: " + type

            # Write the key/value pair to the database
            db.put(kds.input, vds.input)

        except Exception, e:
            print("ERROR writing to wallet.dat, type %s" % type)
            print("data dictionary: %r" % data)
            traceback.print_exc()


def create_new_wallet(db_env, walletfile, version):
    db_out = DB(db_env)

    try:
        r = db_out.open(walletfile, "main", DB_BTREE, DB_CREATE)
    except DBError:
        r = True

    if r is not None:
        logging.error("Couldn't open %s." % walletfile)
        sys.exit(1)

    db_out.put("0776657273696f6e".decode('hex'), ("%08x" % version).decode('hex')[::-1])

    db_out.close()


def rewrite_wallet(db_env, walletfile, destFileName, pre_put_callback=None):
    db = open_wallet(db_env, walletfile)

    db_out = DB(db_env)
    try:
        r = db_out.open(destFileName, "main", DB_BTREE, DB_CREATE)
    except DBError:
        r = True

    if r is not None:
        logging.error("Couldn't open %s." % destFileName)
        sys.exit(1)

    def item_callback(type, d):
        if (pre_put_callback is None or pre_put_callback(type, d)):
            db_out.put(d["__key__"], d["__value__"])

    parse_wallet(db, item_callback)
    db_out.close()
    db.close()


def read_wallet(json_db, db_env, walletfile, print_wallet, print_wallet_transactions, transaction_filter,
                include_balance, vers=-1, FillPool=False):
    global passphrase, addr_to_keys
    crypted = False

    private_keys = []
    private_hex_keys = []

    if vers > -1:
        global addrtype
        oldaddrtype = addrtype
        addrtype = vers

    db = open_wallet(db_env, walletfile, writable=FillPool)

    json_db['keys'] = []
    json_db['pool'] = []
    json_db['tx'] = []
    json_db['names'] = {}
    json_db['ckey'] = []
    json_db['mkey'] = {}

    def item_callback(type, d):
        if type == "tx":
            json_db['tx'].append(
                {"tx_id": d['tx_id'], "txin": d['txIn'], "txout": d['txOut'], "tx_v": d['txv'], "tx_k": d['txk']})

        elif type == "name":
            json_db['names'][d['hash']] = d['name']

        elif type == "version":
            json_db['version'] = d['version']

        elif type == "minversion":
            json_db['minversion'] = d['minversion']

        elif type == "setting":
            if not json_db.has_key('settings'): json_db['settings'] = {}
            json_db["settings"][d['setting']] = d['value']

        elif type == "defaultkey":
            json_db['defaultkey'] = public_key_to_bc_address(d['key'])

        elif type == "key":
            addr = public_key_to_bc_address(d['public_key'])
            compressed = d['public_key'][0] != '\04'
            sec = SecretToASecret(PrivKeyToSecret(d['private_key']), compressed)
            hexsec = ASecretToSecret(sec)[:32].encode('hex')
            private_keys.append(sec)
            addr_to_keys[addr] = [hexsec, d['public_key'].encode('hex')]
            json_db['keys'].append(
                {'addr': addr, 'sec': sec, 'hexsec': hexsec, 'secret': hexsec, 'pubkey': d['public_key'].encode('hex'),
                 'compressed': compressed, 'private': d['private_key'].encode('hex')})

        elif type == "wkey":
            if not json_db.has_key('wkey'): json_db['wkey'] = []
            json_db['wkey']['created'] = d['created']

        elif type == "pool":
            """	d['n'] = kds.read_int64()
				d['nVersion'] = vds.read_int32()
				d['nTime'] = vds.read_int64()
				d['public_key'] = vds.read_bytes(vds.read_compact_size())"""
            try:
                json_db['pool'].append({'n': d['n'], 'addr': public_key_to_bc_address(d['public_key']),
                                        'addr2': public_key_to_bc_address(d['public_key'].decode('hex')),
                                        'addr3': public_key_to_bc_address(d['public_key'].encode('hex')),
                                        'nTime': d['nTime'], 'nVersion': d['nVersion'],
                                        'public_key_hex': d['public_key']})
            except:
                json_db['pool'].append(
                    {'n': d['n'], 'addr': public_key_to_bc_address(d['public_key']), 'nTime': d['nTime'],
                     'nVersion': d['nVersion'], 'public_key_hex': d['public_key'].encode('hex')})

        elif type == "acc":
            json_db['acc'] = d['account']
            print("Account %s (current key: %s)" % (d['account'], public_key_to_bc_address(d['public_key'])))

        elif type == "acentry":
            json_db['acentry'] = (
                d['account'], d['nCreditDebit'], d['otherAccount'], time.ctime(d['nTime']), d['n'], d['comment'])

        elif type == "bestblock":
            json_db['bestblock'] = d['hashes'][0][::-1].encode('hex_codec')

        elif type == "ckey":
            crypted = True
            compressed = d['public_key'][0] != '\04'
            json_db['keys'].append(
                {'pubkey': d['public_key'].encode('hex'), 'addr': public_key_to_bc_address(d['public_key']),
                 'encrypted_privkey': d['encrypted_private_key'].encode('hex_codec'), 'compressed': compressed})

        elif type == "mkey":
            json_db['mkey']['nID'] = d['nID']
            json_db['mkey']['encrypted_key'] = d['encrypted_key'].encode('hex_codec')
            json_db['mkey']['salt'] = d['salt'].encode('hex_codec')
            json_db['mkey']['nDerivationMethod'] = d['nDerivationMethod']
            json_db['mkey']['nDerivationIterations'] = d['nDerivationIterations']
            json_db['mkey']['otherParams'] = d['otherParams']

            if passphrase:
                res = crypter.SetKeyFromPassphrase(passphrase, d['salt'], d['nDerivationIterations'],
                                                   d['nDerivationMethod'])
                if res == 0:
                    logging.error("Unsupported derivation method")
                    sys.exit(1)
                masterkey = crypter.Decrypt(d['encrypted_key'])
                crypter.SetKey(masterkey)

        else:
            json_db[type] = 'unsupported'
            print "Wallet data not recognized: " + str(d)

    list_of_reserve_not_in_pool = []
    parse_wallet(db, item_callback)

    nkeys = len(json_db['keys'])
    i = 0
    for k in json_db['keys']:
        i += 1
        addr = k['addr']
        if include_balance:
            #			print("%3d/%d  %s  %s" % (i, nkeys, k["addr"], k["balance"]))
            k["balance"] = balance(balance_site, k["addr"])
        # print("  %s" % (i, nkeys, k["addr"], k["balance"]))

        if addr in json_db['names'].keys():
            k["label"] = json_db['names'][addr]
            k["reserve"] = 0
        else:
            k["reserve"] = 1
            list_of_reserve_not_in_pool.append(k['pubkey'])

    def rnip_callback(a):
        list_of_reserve_not_in_pool.remove(a['public_key_hex'])

    if FillPool:
        map(rnip_callback, json_db['pool'])

        cpt = 1
        for p in list_of_reserve_not_in_pool:
            update_wallet(db, 'pool', {'public_key': p.decode('hex'), 'n': cpt, 'nTime': ts(), 'nVersion': 80100})
            cpt += 1

    db.close()

    crypted = 'salt' in json_db['mkey']

    if not crypted:
        print "The wallet is not encrypted"

    if crypted and not passphrase:
        print "The wallet is encrypted but no passphrase is used"

    if crypted and passphrase:
        check = True
        ppcorrect = True
        for k in json_db['keys']:
            if 'encrypted_privkey' in k:
                ckey = k['encrypted_privkey'].decode('hex')
                public_key = k['pubkey'].decode('hex')
                crypter.SetIV(Hash(public_key))
                secret = crypter.Decrypt(ckey)
                compressed = public_key[0] != '\04'

                if check:
                    check = False
                    pkey = EC_KEY(int('0x' + secret.encode('hex'), 16))
                    if public_key != GetPubKey(pkey, compressed):
                        print "The wallet is encrypted and the passphrase is incorrect"
                        ppcorrect = False
                        break

                sec = SecretToASecret(secret, compressed)
                k['sec'] = sec
                k['hexsec'] = secret[:32].encode('hex')
                k['secret'] = secret.encode('hex')
                k['compressed'] = compressed
                addr_to_keys[k['addr']] = [sec, k['pubkey']]
                #			del(k['ckey'])
                #			del(k['secret'])
                #			del(k['pubkey'])
                private_keys.append(sec)
        if ppcorrect:
            print "The wallet is encrypted and the passphrase is correct"

    for k in json_db['keys']:
        if k['compressed'] and 'secret' in k:
            k['secret'] += "01"

            #	del(json_db['pool'])
            #	del(json_db['names'])
    if vers > -1:
        addrtype = oldaddrtype

    return {'crypted': crypted}
    # end of bitcointools wallet.dat handling code


def retrieve_last_pywallet_md5():
    global md5_last_pywallet
    md5_last_pywallet = [True, md5_onlinefile('https://raw.github.com/jackjack-jj/pywallet/master/pywallet.py')]


def md5_onlinefile(add):
    page = urllib.urlopen(add).read()
    return md5_2(page)


def restart_pywallet():
    thread.start_new_thread(start_pywallet, ())
    time.sleep(2)
    reactor.stop()


def start_pywallet():
    a = Popen("python " + pyw_path + "/" + pyw_filename + " --web --port " + str(webport) + " --wait 3", shell=True,
              bufsize=-1, stdout=PIPE).stdout
    a.close()


def clone_wallet(parentPath, clonePath):
    types, datas = [], []
    parentdir, parentname = os.path.split(parentPath)
    wdir, wname = os.path.split(clonePath)

    db_env = create_env(parentdir)
    read_wallet(json_db, db_env, parentname, True, True, "", False)

    types.append('version')
    datas.append({'version': json_db['version']})
    types.append('defaultkey')
    datas.append({'key': json_db['defaultkey']})
    for k in json_db['keys']:
        types.append('ckey')
        datas.append(
            {'public_key': k['pubkey'].decode('hex'), 'encrypted_private_key': random_string(96).decode('hex')})
    for k in json_db['pool']:
        types.append('pool')
        datas.append({'n': k['n'], 'nVersion': k['nVersion'], 'nTime': k['nTime'],
                      'public_key': k['public_key_hex'].decode('hex')})
    for addr, label in json_db['names'].items():
        types.append('name')
        datas.append({'hash': addr, 'name': 'Watch:' + label})

    db_env = create_env(wdir)
    create_new_wallet(db_env, wname, 60000)

    db = open_wallet(db_env, wname, True)
    NPP_salt = random_string(16).decode('hex')
    NPP_rounds = int(50000 + random.random() * 20000)
    NPP_method = 0
    NPP_MK = random_string(64).decode('hex')
    crypter.SetKeyFromPassphrase(random_string(64), NPP_salt, NPP_rounds, NPP_method)
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

    read_wallet(json_db, db_env, wname, True, True, "", False)

    db = open_wallet(db_env, wname, writable=True)
    update_wallet(db, types, datas, True)
    db.close()
    print "Wallet successfully cloned to:\n   %s" % clonePath

