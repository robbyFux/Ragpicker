# Copyright (C) 2013-2015 Ragpicker Developers.
# This file is part of Ragpicker Malware Crawler - http://code.google.com/p/malware-crawler/

import logging
import os
import socket
import collections
import tempfile
import utils.magic as magic
import utils.rarfile as rarfile
import utils.socks as socks

from collections import OrderedDict
from os.path import join
from zipfile import ZipFile
from core.config import Config
from core.constants import PERMITTED_TYPES
from core.constants import PRINTABLE_CHARACTERS
from core.constants import RAGPICKER_ROOT

try:
    import jsonpickle
except ImportError:
    raise ImportError, 'jsonpickle library for serialization and deserialization: http://jsonpickle.github.io/'

log = logging.getLogger(__name__)
CFG_CRAWLER = Config(os.path.join(RAGPICKER_ROOT, 'config', 'crawler.conf'))
STR_ZIP = "Zip"
STR_RAR = "RAR"

class DatetimeHandler(jsonpickle.handlers.BaseHandler):
    def flatten(self, obj, data):
        return obj.strftime('%Y-%m-%d %H:%M:%S.%f') 

class UUIDHandler(jsonpickle.handlers.BaseHandler):
    def flatten(self, obj, data):
        return str(obj) 
    
def setTorProxy():
    # TOR Socks proxy
    isTorEnabled = CFG_CRAWLER.get("clientConfig").get("tor_enabled", False)
    
    if isTorEnabled:
        torProxyAdress = CFG_CRAWLER.get("clientConfig").get("tor_proxyadress", "localhost")
        torProxyPort = CFG_CRAWLER.get("clientConfig").get("tor_proxyport", 9050)
        # Route an HTTP request through the SOCKS proxy 
        socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, torProxyAdress, torProxyPort)
        socket.socket = socks.socksocket

def processYara(rulepath, filepath=None, data=None, prefix=None):
    # Check YARA
    try:
        import yara
    except ImportError:
        raise ImportError, 'Python-Yara is required to run this program: https://github.com/plusvic/yara'
        
    result = []
    
    try:
        rules = yara.compile(rulepath)
        yaraHits = None
        
        if filepath:
            yaraHits = rules.match(filepath=filepath)
        elif data:
            yaraHits = rules.match(data=data)
        
        for hit in yaraHits:
            hitstrings = []
            
            for key, stringname, val in hit.strings:
                hitstrings.append("%s = %s" % (stringname, convertYaraString(val)))
            
            #Delete duplicate values
            hitstrings = list(set(hitstrings))
            
            #Prefix eg. UnpackedFile
            if prefix:
                ruleName = prefix + "_" + hit.rule
            else:
                ruleName = hit.rule
            
            result.append({"rule": ruleName, "meta":hit.meta, "strings":hitstrings})

    except (Exception) as e:
        log.error("Process Yara returned the following error: %s" % e)
        
    return result

def convertYaraString(sval):
    sb = []
    for char in sval:
        if char not in (PRINTABLE_CHARACTERS):
            hex = format(ord(char), "x").upper()
            if hex == "0":
                hex = "00"
            sb.append(hex)
        else:
            sb.append(char)
    
    return ''.join(sb)

def flatten_dict(d, parent_key='', sep='_'):
    items = []
    for k, v in d.items():
        new_key = parent_key + sep + k if parent_key else k
        if isinstance(v, collections.MutableMapping):
            items.extend(flatten_dict(v, new_key).items())
        else:
            items.append((new_key, v))
    return dict(items)

def convertDirtyDict2ASCII(data):
    if data is None or isinstance(data, (bool, int, long, float)):
        return data
    if isinstance(data, basestring):
        return convert2printable(data)
    if isinstance(data, list):
        return [convertDirtyDict2ASCII(val) for val in data]
    if isinstance(data, OrderedDict):
        return [[convertDirtyDict2ASCII(k), convertDirtyDict2ASCII(v)] for k, v in data.iteritems()]
    if isinstance(data, dict):
        if all(isinstance(k, basestring) for k in data):
            return {k: convertDirtyDict2ASCII(v) for k, v in data.iteritems()}
        return [[convertDirtyDict2ASCII(k), convertDirtyDict2ASCII(v)] for k, v in data.iteritems()]
    if isinstance(data, tuple):
        return [convertDirtyDict2ASCII(val) for val in data]
    if isinstance(data, set):
        return [convertDirtyDict2ASCII(val) for val in data]
    
    return data

def convert2printable(s):
    if not isinstance(s, basestring) or isPrintable(s):
        return s
    return "".join(convertChar(c) for c in s)

def convertChar(c):
    if c in PRINTABLE_CHARACTERS:
        return c
    else:
        return "?"

def isPrintable(s):
    for c in s:
        if not c in PRINTABLE_CHARACTERS:
            return False
    return True

# Liefert einen Temporaeren-Dateinamen
def getTmpFileName():
    tmppath = tempfile.gettempdir()
    targetpath = os.path.join(tmppath, "ragpicker-tmp")
    if not os.path.exists(targetpath):
        os.mkdir(targetpath)
        
    tf = tempfile.NamedTemporaryFile(dir=targetpath, suffix='.virus', prefix='ragpicker_',)
    tempfileName = tf.name
    tf.close()
        
    log.debug("tempfileName=%s" % tempfileName)
    return tempfileName

def getFileTypeFromBuffer(file_data):
    """Get MIME file type.
    @return: file type.
    """
    filetype = magic.from_buffer(file_data)
    filetype = filetype.split(' ')[0]
    return filetype 

def getFileType(file_path):
    """Get MIME file type.
    @return: file type.
    """
    try:
        file_type = magic.from_file(file_path)
    except:
        try:
            import subprocess
            file_process = subprocess.Popen(['file', '-b', file_path],
                                            stdout=subprocess.PIPE)
            file_type = file_process.stdout.read().strip()
        except:
            return None

    file_type = file_type.split(' ')[0]
    
    return file_type

def isPermittedType(file_path):
    filetype = getFileType(file_path)
    
    for x in PERMITTED_TYPES:
        if filetype.__contains__(x):
            return True
    return False

#-----------------------------------------------------------------------------
# Unpack archive functions (ZIP and RAR)
# Recurse unpack archive to tempdir
#-----------------------------------------------------------------------------
def unpackArchive(fileName, tmpdir=None):
    oDir = getExpandedDirName(fileName)
    
    if tmpdir:
        oDir = join(tmpdir, os.path.basename(oDir))
    
    os.makedirs(oDir)
    
    if getFileType(fileName) == STR_ZIP:
        zip = ZipFile(fileName)
        zip.extractall(path=oDir)
    elif getFileType(fileName) == STR_RAR:
        rar = rarfile.RarFile(fileName)
        rar.extractall(path=oDir)
        
    walkFiles(oDir)
    
def walkFiles(dirName):
    dirs = os.walk(dirName)
    
    for (dirPath, dirNames, fileNames) in dirs:
        for fileName in fileNames:
            if isArchive(os.path.join(dirPath, fileName)):
                unpackArchive(os.path.join(dirPath, fileName))
 
def getExpandedDirName(fileName):
    fileDir = os.path.dirname(fileName)
    baseName = "%s.contents" % os.path.basename(fileName)
    
    return os.path.join(fileDir, baseName)
 
def isArchive(file_path):
    filetype = getFileType(file_path)
    
    for x in [STR_ZIP, STR_RAR]:
        if filetype.__contains__(x):
            return True
    return False

def uniqueList(l):
    ulist = []
    [ulist.append(x) for x in l if x not in ulist]
    return ulist