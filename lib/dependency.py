from constants import *
try:
    from bsddb.db import *
except:
    try:
        from bsddb3.db import *
    except:
        missing_dep.append('bsddb')

import os, sys, time, re
import os.path
import platform

try:
    for i in os.listdir('/usr/lib/python2.5/site-packages'):
        if 'Twisted' in i:
            sys.path.append('/usr/lib/python2.5/site-packages/' + i)
except:
    ''

try:
    import json
except:
    try:
        import simplejson as json
    except:
        print("Json or simplejson package is needed")

import logging
import struct
import traceback
import socket
import hashlib
import random
import urllib
import math

try:
    from twisted.internet import reactor
    from twisted.web import server, resource
    from twisted.web.static import File
    from twisted.python import log
except:
    missing_dep.append('twisted')


from datetime import datetime
from subprocess import *


def iais(a):
    if a >= 2:
        return 's'
    else:
        return ''


# return system type
def systype():
    if platform.system() == "Darwin":
        return 'Mac'
    elif platform.system() == "Windows":
        return 'Win'
    return 'Linux'


def get_keys(d, value):
    return [k for k, v in d.items() if v == value]


def determine_db_dir():
    if wallet_dir in "":
        if platform.system() == "Darwin":
            return os.path.expanduser("~/Library/Application Support/Bitcoin/")
        elif platform.system() == "Windows":
            return os.path.join(os.environ['APPDATA'], "Bitcoin")
        return os.path.expanduser("~/.bitcoin")
    else:
        return wallet_dir


def determine_db_name():
    if wallet_name in "":
        return "wallet.dat"
    else:
        return wallet_name

def create_env(db_dir):
    db_env = DBEnv(0)
    r = db_env.open(db_dir,
                    (DB_CREATE | DB_INIT_LOCK | DB_INIT_LOG | DB_INIT_MPOOL | DB_INIT_TXN | DB_THREAD | DB_RECOVER))
    return db_env

# timestamp
def ts():
    return int(time.mktime(datetime.now().timetuple()))

