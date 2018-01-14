#!/usr/bin/env python
# -*- coding: utf-8 -*-

from lib.constants import *
from lib.dependency import *
from lib.ECDSA_constants import *
from crypter import *
from ECDSA import *
from hash import *
from key import *

##readed
##Inc 10240
def search_patterns_on_disk(device, size, inc, patternlist):  # inc must be higher than 1k
    try:
        otype = os.O_RDONLY | os.O_BINARY
    except:
        otype = os.O_RDONLY
    try:
        fd = os.open(device, otype)
    except Exception as e:
        print "Can't open %s, check the path or try as root" % device
        print "  Error:", e.args
        exit(0)

    i = 0
    data = ''

    tzero = time.time()
    sizetokeep = 0
    # patternlist ['\t\x00\x01\x04mkey', "'\x00\x01\x04ckey", '\x00\x01\x03key']
    # map(function, iterable, ...)
    BlocksToInspect = dict(map(lambda x: [x, []], patternlist))
    # {'\x00\x01\x03key': [], "'\x00\x01\x04ckey": [], '\t\x00\x01\x04mkey': []}
    syst = systype()
    lendataloaded = None
    writeProgressEvery = 100 * Mo
    while i < int(size) and (lendataloaded != 0 or lendataloaded == None):
        if int(i / writeProgressEvery) != int((i + inc) / writeProgressEvery):
            print "%.2f Go read" % (i / 1e9)
        try:
            datakept = data[-sizetokeep:]
            # inc 读取的的字节
            data = datakept + os.read(fd, inc)
            lendataloaded = len(data) - len(datakept)  # should be inc
            for text in patternlist:
                if text in data:
                    BlocksToInspect[text].append([i - len(datakept), data, len(datakept)])
                    pass
            sizetokeep = 80  # 20 because all the patterns have a len<20. Could be higher.
            i += lendataloaded
        except Exception as exc:
            if lendataloaded % 512 > 0:
                raise Exception("SPOD error 1: %d, %d" % (lendataloaded, i - len(datakept)))
            os.lseek(fd, lendataloaded, os.SEEK_CUR)
            print str(exc)
            i += lendataloaded
            continue
    os.close(fd)

    # {'\x00\x01\x03key': [], "'\x00\x01\x04ckey": [], '\t\x00\x01\x04mkey': []}
    AllOffsets = dict(map(lambda x: [x, []], patternlist))

    for text, blocks in BlocksToInspect.items():
        for offset, data, ldk in blocks:  # ldk = len(datakept)
            offsetslist = [offset + m.start() for m in re.finditer(text, data)]
            AllOffsets[text].extend(offsetslist)

    AllOffsets['PRFdevice'] = device
    AllOffsets['PRFdt'] = time.time() - tzero
    #file position that mathces the patterns
    AllOffsets['PRFsize'] = i
    return AllOffsets


def multiextract(s, ll):
    r = []
    cursor = 0
    for length in ll:
        r.append(s[cursor:cursor + length])
        cursor += length
    if s[cursor:] != '':
        r.append(s[cursor:])
    return r


class RecovCkey(object):
    def __init__(self, epk, pk):
        self.encrypted_pk = epk
        self.public_key = pk
        self.mkey = None
        self.privkey = None


class RecovMkey(object):
    def __init__(self, ekey, salt, nditer, ndmethod, nid):
        self.encrypted_key = ekey
        self.salt = salt
        self.iterations = nditer
        self.method = ndmethod
        self.id = nid


def readpartfile(fd, offset, length):  # make everything 512*n because of windows...
    rest = offset % 512
    new_offset = offset - rest
    big_length = 512 * (int((length + rest - 1) / 512) + 1)
    #
    os.lseek(fd, new_offset, os.SEEK_SET)
    d = os.read(fd, big_length)
    return d[rest:rest + length]


#similiar to recov mkey
def recov_ckey(fd, offset):
    d = readpartfile(fd, offset - 49, 122)
    me = multiextract(d, [1, 48, 4, 4, 1])

    checks = []
    checks.append([0, '30'])
    checks.append([3, '636b6579'])
    if sum(map(lambda x: int(me[x[0]] != x[1].decode('hex')), checks)):  # number of false statements
        return None

    return me


# offset eg:52628
# return eg:['C\x00\x010', '\xe5\x89\x9bfjtq\xed\xe4\n<\xdb\x87=\xaf\x86X\xb0\x19\x17BZ\x8b\xb2\x11\x100\xf0\xf7\xdf\x17\xc4Ft2\x19\xfb\x825\xb3\x93A\xe3*|y\x8c\xb3',
# '\x08', '\xcb\x98J\xfet}\x0b\xc5',
# '\x00\x00\x00\x00', '\x89\x13\x02\x00', '\x00', '\xe2P', '\t\x00\x01\x04mkey', '\x01\x00\x00\x00']
def recov_mkey(fd, offset):
    d = readpartfile(fd, offset - 72, 84)
    #devide the mkey related bytes into parts
    me = multiextract(d, [4, 48, 1, 8, 4, 4, 1, 2, 8, 4])
    checks = []
    checks.append([0, '43000130'])
    checks.append([2, '08'])
    checks.append([6, '00'])
    checks.append([8, '090001046d6b6579'])

    #compare the index(0,2,6,8) items in me to checks[]..decode('hex') are the same..
    #'C\x00\x010' '\x08' '\x00'  '\t\x00\x01\x04mkey'
    if sum(map(lambda x: int(me[x[0]] != x[1].decode('hex')), checks)):  # number of false statements
        return None
    return me


def recov_uckey(fd, offset):
    checks = []

    d = readpartfile(fd, offset - 217, 223)
    if d[-7] == '\x26':
        me = multiextract(d, [2, 1, 4, 1, 32, 141, 33, 2, 1, 6])

        checks.append([0, '3081'])
        checks.append([2, '02010104'])
    elif d[-7] == '\x46':
        d = readpartfile(fd, offset - 282, 286)

        me = multiextract(d, [2, 1, 4, 1, 32, 173, 65, 1, 2, 5])

        checks.append([0, '8201'])
        checks.append([2, '02010104'])
        checks.append([-1, '460001036b'])
    else:
        return None

    if sum(map(lambda x: int(me[x[0]] != x[1].decode('hex')), checks)):  # number of false statements
        return None

    return me


def starts_with(s, b):
    return len(s) >= len(b) and s[:len(b)] == b


##reading
def recov(device, passes, size=102400, inc=10240, outputdir='.'):
    if inc % 512 > 0:
        inc -= inc % 512  # inc must be 512*n on Windows... Don't ask me why...

    nameToDBName = {'mkey': '\x09\x00\x01\x04mkey', 'ckey': '\x27\x00\x01\x04ckey', 'key': '\x00\x01\x03key',}

    if not starts_with(device, 'PartialRecoveryFile:'):
        # get the blocks of founded data
        r = search_patterns_on_disk(device, size, inc, map(lambda x: nameToDBName[x], ['mkey', 'ckey', 'key']))
        f = open(outputdir + '/pywallet_partial_recovery_%d.dat' % ts(), 'w')
        f.write(str(r))
        f.close()
        print "\nRead %.1f Go in %.1f minutes\n" % (r['PRFsize'] / 1e9, r['PRFdt'] / 60.0)
    else:
        prf = device[20:]
        f = open(prf, 'r')
        content = f.read()
        f.close()
        cmd = ("z = " + content + "")
        exec cmd in locals()
        r = z
        device = r['PRFdevice']
        print "\nLoaded %.1f Go from %s\n" % (r['PRFsize'] / 1e9, device)

    try:
        otype = os.O_RDONLY | os.O_BINARY
    except:
        otype = os.O_RDONLY
    fd = os.open(device, otype)

    mkeys = []
    crypters = []
    syst = systype()
    for offset in r[nameToDBName['mkey']]:
        s = recov_mkey(fd, offset)
        if s == None:
            continue
        # ekey, salt, nditer, ndmethod, nid
        # eg for 52628 s[1]:'\xe5\x89\x9bfjtq\xed\xe4\n<\xdb\x87=\xaf\x86X\xb0\x19\x17BZ\x8b\xb2\x11\x100\xf0\xf7\xdf\x17\xc4Ft2\x19\xfb\x825\xb3\x93A\xe3*|y\x8c\xb3'
        # s[3]'\xcb\x98J\xfet}\x0b\xc5'
        # 136073,0, 1
        # the sequence is inverse
        newmkey = RecovMkey(s[1], s[3], int(s[5][::-1].encode('hex'), 16), int(s[4][::-1].encode('hex'), 16),
                            int(s[-1][::-1].encode('hex'), 16))
        mkeys.append([offset, newmkey])

    print "Found", len(mkeys), 'possible wallets'

    ckeys = []
    for offset in r[nameToDBName['ckey']]:
        s = recov_ckey(fd, offset)
        if s == None:
            continue
        newckey = RecovCkey(s[1], s[5][:int(s[4].encode('hex'), 16)])
        ckeys.append([offset, newckey])
    print "Found", len(ckeys), 'possible encrypted keys'

    uckeys = []
    for offset in r[nameToDBName['key']]:
        s = recov_uckey(fd, offset)
        if s == None:
            continue
        uckeys.append(s[4])
    print "Found", len(uckeys), 'possible unencrypted keys'

    os.close(fd)

    #reading
    #{mkey:[]}
    list_of_possible_keys_per_master_key = dict(map(lambda x: [x[1], []], mkeys))
    for cko, ck in ckeys:
        tl = map(lambda x: [abs(x[0] - cko)] + x, mkeys)
        tl = sorted(tl, key=lambda x: x[0])
        list_of_possible_keys_per_master_key[tl[0][2]].append(ck)

    cpt = 0
    mki = 1
    tzero = time.time()
    if len(passes) == 0:
        if len(ckeys) > 0:
            print "Can't decrypt them as you didn't provide any passphrase."
    else:
        for mko, mk in mkeys:
            list_of_possible_keys = list_of_possible_keys_per_master_key[mk]
            sys.stdout.write("\nPossible wallet #" + str(mki))
            sys.stdout.flush()
            for ppi, pp in enumerate(passes):
                sys.stdout.write("\n    with passphrase #" + str(ppi + 1) + "  ")
                sys.stdout.flush()
                failures_in_a_row = 0
                print "SKFP params:", pp, "1", mk.salt, "2", mk.iterations, "3", mk.method, "4", crypter
                res = crypter.SetKeyFromPassphrase(pp, mk.salt, mk.iterations, mk.method)
                if res == 0:
                    print "Unsupported derivation method"
                    sys.exit(1)
                masterkey = crypter.Decrypt(mk.encrypted_key)
                crypter.SetKey(masterkey)
                print 'after'
                for ck in list_of_possible_keys:
                    if cpt % 10 == 9 and failures_in_a_row == 0:
                        sys.stdout.write('.')
                        sys.stdout.flush()
                    if failures_in_a_row > 5:
                        break
                    crypter.SetIV(Hash(ck.public_key))
                    secret = crypter.Decrypt(ck.encrypted_pk)
                    compressed = ck.public_key[0] != '\04'

                    pkey = EC_KEY(int('0x' + secret.encode('hex'), 16))
                    if ck.public_key != GetPubKey(pkey, compressed):
                        failures_in_a_row += 1
                    else:
                        failures_in_a_row = 0
                        ck.mkey = mk
                        ck.privkey = secret
                    cpt += 1
            mki += 1
        print "\n"
        tone = time.time()
        try:
            calcspeed = 1.0 * cpt / (tone - tzero) * 60  # calc/min
        except:
            calcspeed = 1.0
        if calcspeed == 0:
            calcspeed = 1.0

        ckeys_not_decrypted = filter(lambda x: x[1].privkey == None, ckeys)
        refused_to_test_all_pps = True
        if len(ckeys_not_decrypted) == 0:
            print "All the found encrypted private keys have been decrypted."
            return map(lambda x: x[1].privkey, ckeys)
        else:
            print "Private keys not decrypted: %d" % len(ckeys_not_decrypted)
            print "Trying all the remaining possibilities (%d) might take up to %d minutes." % (
                len(ckeys_not_decrypted) * len(passes) * len(mkeys),
                int(len(ckeys_not_decrypted) * len(passes) * len(mkeys) / calcspeed))
            cont = raw_input("Do you want to test them? (y/n): ")
            while len(cont) == 0:
                cont = raw_input("Do you want to test them? (y/n): ")
            if cont[0] == 'y':
                refused_to_test_all_pps = False
                cpt = 0
                for dist, mko, mk in tl:
                    for ppi, pp in enumerate(passes):
                        res = crypter.SetKeyFromPassphrase(pp, mk.salt, mk.iterations, mk.method)
                        if res == 0:
                            logging.error("Unsupported derivation method")
                            sys.exit(1)
                        masterkey = crypter.Decrypt(mk.encrypted_key)
                        crypter.SetKey(masterkey)
                        for cko, ck in ckeys_not_decrypted:
                            tl = map(lambda x: [abs(x[0] - cko)] + x, mkeys)
                            tl = sorted(tl, key=lambda x: x[0])
                            if mk == tl[0][2]:
                                continue  # because already tested
                            crypter.SetIV(Hash(ck.public_key))
                            secret = crypter.Decrypt(ck.encrypted_pk)
                            compressed = ck.public_key[0] != '\04'

                            pkey = EC_KEY(int('0x' + secret.encode('hex'), 16))
                            if ck.public_key == GetPubKey(pkey, compressed):
                                ck.mkey = mk
                                ck.privkey = secret
                            cpt += 1

        print
        ckeys_not_decrypted = filter(lambda x: x[1].privkey == None, ckeys)
        if len(ckeys_not_decrypted) == 0:
            print "All the found encrypted private keys have been finally decrypted."
        elif not refused_to_test_all_pps:
            print "Private keys not decrypted: %d" % len(ckeys_not_decrypted)
            print "Try another password, check the size of your partition or seek help"

    uncrypted_ckeys = filter(lambda x: x != None, map(lambda x: x[1].privkey, ckeys))
    uckeys.extend(uncrypted_ckeys)

    return uckeys

def shrink_intervals(device, ranges, prekeys, inc=1000):
    prekey = prekeys[0]
    nranges = []
    fd = os.open(device, os.O_RDONLY)
    for j in range(len(ranges) / 2):
        before_contained_key = False
        contains_key = False
        bi = ranges[2 * j]
        bf = ranges[2 * j + 1]

        mini_blocks = []
        k = bi
        while k <= bf + len(prekey) + 1:
            mini_blocks.append(k)
            k += inc
            mini_blocks.append(k)

        for k in range(len(mini_blocks) / 2):
            mini_blocks[2 * k] -= len(prekey) + 1
            mini_blocks[2 * k + 1] += len(prekey) + 1

            bi = mini_blocks[2 * k]
            bf = mini_blocks[2 * k + 1]

            os.lseek(fd, bi, 0)

            data = os.read(fd, bf - bi + 1)
            contains_key = one_element_in(prekeys, data)

            if not before_contained_key and contains_key:
                nranges.append(bi)

            if before_contained_key and not contains_key:
                nranges.append(bi + len(prekey) + 1 + len(prekey) + 1)

            before_contained_key = contains_key

    os.close(fd)

    return nranges


def find_offsets(device, ranges, prekeys):
    prekey = prekeys[0]
    list_offsets = []
    to_read = 0
    fd = os.open(device, os.O_RDONLY)
    for i in range(len(ranges) / 2):
        bi = ranges[2 * i] - len(prekey) - 1
        os.lseek(fd, bi, 0)
        bf = ranges[2 * i + 1] + len(prekey) + 1
        to_read += bf - bi + 1
        buf = ""
        for j in range(len(prekey)):
            buf += "\x00"
        curs = bi

        while curs <= bf:
            data = os.read(fd, 1)
            buf = buf[1:] + data
            if buf in prekeys:
                list_offsets.append(curs)
            curs += 1

    os.close(fd)

    return [to_read, list_offsets]


def read_keys(device, list_offsets):
    found_hexkeys = []
    fd = os.open(device, os.O_RDONLY)
    for offset in list_offsets:
        os.lseek(fd, offset + 1, 0)
        data = os.read(fd, 40)
        hexkey = data[1:33].encode('hex')
        after_key = data[33:39].encode('hex')
        if hexkey not in found_hexkeys and check_postkeys(after_key.decode('hex'), postkeys):
            found_hexkeys.append(hexkey)

    os.close(fd)

    return found_hexkeys


# calculate the size provided
def read_device_size(size):
    if size[-2] == 'i':
        unit = size[-3:]
        value = float(size[:-3])
    else:
        unit = size[-2:]
        value = float(size[:-2])
    exec 'unit = %s' % unit
    return int(value * unit)