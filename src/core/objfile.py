# Copyright (C) 2013-2015 Ragpicker Developers.
# This file is part of Ragpicker Malware Crawler - http://code.google.com/p/malware-crawler/

from urlparse import urlparse
import base64
import hashlib
import logging
import os
import shutil
import uuid

from core.commonutils import getFileType
from core.commonutils import getTmpFileName
from core.commonutils import convertDirtyDict2ASCII
from core.constants import PERMITTED_TYPES

FILE_CHUNK_SIZE = 16 * 1024
log = logging.getLogger(__name__)

class Family:
    
    def __init__(self, uuid):
        self.uuid = uuid 
        self.parentObjectSHA256 = ""
        self.unpackedObjectSHA256 = ""
        self.siblingObjectsSHA256 = []
        
    def setParentObjectSHA256(self, sha256):
        self.parentObjectSHA256 = sha256
        
    def setUnpackedObjectSHA256(self, sha256):
        self.unpackedObjectSHA256 = sha256
        
    def addSiblingObjectSHA256(self, sha256):
        self.siblingObjectsSHA256.append(sha256)
        
    def __dict__(self):
        family = {}
        family["uuid"] = self.uuid
        family["parentObjectSHA256"] = self.parentObjectSHA256
        
        if self.unpackedObjectMD5 != "":
            family["unpackedObjectSHA256"] = self.unpackedObjectSHA256
        if len(self.siblingObjectsSHA256) > 0:
            family["siblingObjectsSHA256"] = self.siblingObjectsSHA256
        
        return family
        
class File:
    
    def __init__(self): 
        self.file_data = ""
        self.temp_file = ""
        
    # Copiert ein RawFile in /temp/ragpicker_temp und setzt Stream file_data
    def set_raw_file(self, raw_file):
        # Copy File to ragpicker-temp and save in 
        tmpFile = getTmpFileName()
        shutil.copy2(raw_file, tmpFile)
        self.temp_file = tmpFile
        self.file_data = open(self.temp_file, "rb").read()
        
        # File consistency check
        tempMd5 = self._get_md5(self.temp_file)
        dataMd5 = hashlib.md5(self.file_data).hexdigest()
        
        log.debug("DataMd5=%s and TempFileMd5=%s" % (dataMd5, tempMd5))
        
        if dataMd5 != tempMd5:
            log.error("File not consistent DataMd5=%s and TempFileMd5=%s" % (dataMd5, tempMd5))
            raise Exception("File not consistent DataMd5=%s and TempFileMd5=%s" % (dataMd5, tempMd5)) 
                    
    # Speichert Stream in file_data und erstellt ein temp_file unter /temp/ragpicker_temp
    def set_file_data(self, file_data):
        self.file_data = file_data
        
        # Tmp-File erzeugen
        try:        
            self.temp_file = getTmpFileName()
            
            file = open(self.temp_file, 'wb')
            file.write(file_data)
            file.seek(0)
            file.close
            
            # File consistency check
            tempMd5 = self._get_md5(self.temp_file)
            dataMd5 = hashlib.md5(file_data).hexdigest()
            
            log.debug("DataMd5=%s and TempFileMd5=%s" % (dataMd5, tempMd5))
            
            if dataMd5 != tempMd5:
                log.error("File not consistent DataMd5=%s and TempFileMd5=%s" % (dataMd5, tempMd5))
                raise Exception("File not consistent DataMd5=%s and TempFileMd5=%s" % (dataMd5, tempMd5))             
            
            log.debug("temp_file=%s" % self.temp_file)  
        except Exception, e:
            log.error("Error - Unable to create tempFile")
            raise Exception("Error - Unable to create tempFile") 

    def get_type(self):
        """Get MIME file type.
        @return: file type.
        """
        return getFileType(self.temp_file)
    
    def get_fileB64encode(self):  
        with open(self.temp_file, "rb") as raw_file:
            encoded_file = base64.b64encode(raw_file.read())
        return encoded_file  
    
    def _get_md5(self, filePath):
        with open(filePath, 'rb') as fh:
            m = hashlib.md5()
            while True:
                data = fh.read(FILE_CHUNK_SIZE)
                if not data:
                    break
                m.update(data)
            
            md5 = m.hexdigest()
            log.debug("%s MD5= %s" % (filePath, md5))
            return md5
        
    def get_fileMd5(self):
        md5 = hashlib.md5(self.file_data).hexdigest()
        return str(md5)

    def get_fileSha1(self):
        sha1 = hashlib.sha1(self.file_data).hexdigest()
        return str(sha1)
    
    def get_fileSha256(self):
        sha256 = hashlib.sha256(self.file_data).hexdigest()
        return str(sha256)        
    
    def is_permittedType(self):
        filetype = getFileType(self.temp_file)
        
        for x in PERMITTED_TYPES:
            if filetype.__contains__(x):
                return True
        return False
    
    def get_size(self):
        return os.path.getsize(self.temp_file)    
    
    def file_extension(self):
        file_type = getFileType(self.temp_file)
        
        if not file_type:
            return None
    
        if "DLL" in file_type:
            return "dll"
        elif "PE32" in file_type or "MS-DOS" in file_type:
            return "exe"
        elif "Zip" in file_type:
            return "zip"
        elif "Rar" in file_type:
            return "rar"        
        elif "PDF" in file_type:
            return "pdf"
        elif "Rich" in file_type:
            return "rtf"
        elif "Composite" in file_type:
            return "office"
        elif "HTML" in file_type:
            return "html"
        else:
            return "none"
        
    def close(self):  
        try:
            log.info("Close tmpFile: %s" % self.temp_file)
            os.remove(self.temp_file) 
        except Exception:
            exit  

class ObjFile:
    
    def __init__(self, url): 
        self.uuid = str(uuid.uuid1())
        self.family = Family(self.uuid)
        self.url = url
        self.file = ""
        self.unpacked_file = ""
        self.included_files = []
    
    def set_file_from_path(self, file_path):
        file = File()
        file.set_raw_file(file_path)
        self.file = file
        self.family.setParentObjectSHA256(file.get_fileSha256())
        log.info("set_file_from_path: " + file.get_fileSha256())
        
    def set_file_from_stream(self, file_data):
        file = File()
        file.set_file_data(file_data)
        self.file = file
        self.family.setParentObjectSHA256(file.get_fileSha256())
        
    def set_unpacked_file(self, raw_file):
        file = File()
        file.set_raw_file(raw_file)
        self.unpacked_file = file
        self.family.setUnpackedObjectSHA256(file.get_fileSha256())
        log.info("set_unpacked_file: " + file.get_fileSha256())
        
    def add_included_file(self, file_data):
        file = File()
        file.set_file_data(file_data)
        self.included_files.append(file)
        self.family.addSiblingObjectSHA256(file.get_fileSha256())
        log.info("add_included_file: " + file.get_fileSha256())
        
    def close(self):  
        if self.file:
            self.file.close()
        if self.unpacked_file:
            self.unpacked_file.close()
        if len(self.included_files) > 0:
            for incl_file in self.included_files:
                incl_file.close()
    
    def get_uuid(self):
        return self.uuid    
    
    def get_url_hostname(self):
        o = urlparse(self.url)
        return o.hostname
    
    def get_url_protocol(self):
        o = urlparse(self.url)
        return o.scheme
    
    def get_url_port(self):
        o = urlparse(self.url)
        return o.port
    
    def get_urlMd5(self):
        md5 = hashlib.md5(self.url).hexdigest()
        return str(md5)     
    
    def get_url_filename(self):
        unknownFilename = "unknown_" + self.file.get_fileMd5() + "." + self.file.file_extension()
        urlpath, urlFileName = os.path.split(self.url)
    
        if ("&%" in urlFileName):
            urlFileName = urlFileName[urlFileName.rfind("&%") + 4:]
        if ("=%" in urlFileName):
            urlFileName = urlFileName[urlFileName.rfind("=%") + 4:]
            
        if ("&" in urlFileName):
            urlFileName = urlFileName[urlFileName.rfind("&") + 1:]
        if ("+" in urlFileName):
            urlFileName = urlFileName.replace("+", "_")
        if ("=" in urlFileName):
            urlFileName = urlFileName[urlFileName.rfind("=") + 1:]
        if (":" in urlFileName):
            urlFileName = urlFileName[urlFileName.rfind(":") + 1:]
        if ("#" in urlFileName):
            urlFileName = urlFileName.replace("#", "")
        if ("%" in urlFileName):
            urlFileName = urlFileName.replace("%", "#")
        if ("?" in urlFileName):
            urlFileName = urlFileName[urlFileName.rfind("?") + 1:]
        if ("!" in urlFileName):
            urlFileName = urlFileName[urlFileName.rfind("!") + 1:]
        if ("$" in urlFileName):
            urlFileName = urlFileName[urlFileName.rfind("$") + 1:]
        if ("'" in urlFileName):
            urlFileName = urlFileName.replace("'", "")
        if ("," in urlFileName):
            urlFileName = urlFileName[urlFileName.rfind(",") + 1:]
        if (";" in urlFileName):
            urlFileName = urlFileName[urlFileName.rfind(";") + 1:]
        
        if (len(urlFileName) > 40):
            
            extension = ""
            if "." in urlFileName:
                extension = urlFileName[urlFileName.rfind(".") + 1:]
                urlFileName = urlFileName[:urlFileName.rfind(".")]
            urlFileName = "%s[...].%s" % (urlFileName[:40], extension)
    
        # Verstueckelter Name, bringt nix.    
        if (len(urlFileName) < 3): return unknownFilename
        
        if (urlFileName[0] == "_") or (urlFileName[0] == "-") or (urlFileName[0] == "#"):
            urlFileName = urlFileName[1:]
            
        if not urlFileName or urlFileName == "":
            urlFileName = unknownFilename   
            
        return convertDirtyDict2ASCII(urlFileName).strip()
