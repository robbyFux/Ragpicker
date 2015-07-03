# Copyright (C) 2013-2015 Ragpicker Developers.
# This file is part of Ragpicker Malware Crawler - http://code.google.com/p/malware-crawler/

import os
import json
import logging
import urllib
import urllib2

from core.config import Config
from utils.multiPartForm import MultiPartForm
from core.constants import RAGPICKER_ROOT

VXCAGE_URL_ADD = "http://%s:%s/malware/add"
VXCAGE_URL_FIND = "http://%s:%s/malware/find"

log = logging.getLogger("VxCageHandler")

class VxCageHandler():
    
    def __init__(self):
        self.cfgReporting = Config(os.path.join(RAGPICKER_ROOT, 'config', 'reporting.conf'))
        self.vxcageEnabled = self.cfgReporting.getOption("vxcage", "enabled")
        self.host = self.cfgReporting.getOption("vxcage", "host")
        self.port = self.cfgReporting.getOption("vxcage", "port")
        
        if not self.host or not self.port:
            raise Exception("VxCage REST API server not configurated")
    
    def upload(self, filePath, fileName, tags):
        rawFile = open(filePath, 'rb')
        log.debug(VXCAGE_URL_ADD % (self.host, self.port) + " file=" + fileName)
        
        try:                
            form = MultiPartForm()
            form.add_file('file', fileName, fileHandle=rawFile)
            form.add_field('tags', tags)
            
            request = urllib2.Request(VXCAGE_URL_ADD % (self.host, self.port))
            body = str(form)
            request.add_header('Content-type', form.get_content_type())
            request.add_header('Content-length', len(body))
            request.add_data(body)
            
            response_data = urllib2.urlopen(request, timeout=60).read() 
            reponsejson = json.loads(response_data)           
            log.info("Submitted to vxcage, message: %s", reponsejson["message"])   
        except urllib2.URLError as e:
            raise Exception("Unable to establish connection to VxCage REST API server: %s" % e)
        except urllib2.HTTPError as e:
            raise Exception("Unable to perform HTTP request to VxCage REST API server (http code=%s)" % e) 
        except ValueError as e:
            raise Exception("Unable to convert response to JSON: %s" % e)
        
        if reponsejson["message"] != 'added':
            raise Exception("Failed to store file in VxCage: %s" % reponsejson["message"])
        
    # Exports malware file from the VxCage using the sha256-hash
    def exportVxCage(self, sha256, exportDir):
        if os.path.isfile(exportDir + sha256):
            raise Exception("File %s already exists.") 
        
        cmd = "wget -q --tries=1 --directory-prefix=%s 'http://%s:%s/malware/get/%s'" % (exportDir, self.host, self.port, sha256)
        os.system(cmd)
    
        if not os.path.isfile(exportDir + sha256):
            raise Exception("Download %s failed." % sha256)
        
    def isFileInCage(self, md5=None, sha256=None):
        if md5:
            param = { 'md5': md5 }
        elif sha256:
            param = { 'sha256': sha256 }
        
        request_data = urllib.urlencode(param)
    
        try:
            request = urllib2.Request(VXCAGE_URL_FIND % (self.host, self.port), request_data)
            response = urllib2.urlopen(request, timeout=60)
            response_data = response.read()
        except urllib2.HTTPError as e:
            if e.code == 404:
                # Error: 404 Not Found
                log.info('404 Not Found (' + str(param) + ')')
                return False
            else:
                raise Exception("Unable to perform HTTP request to VxCage (http code=%s)" % e)
        except urllib2.URLError as e:    
            raise Exception("Unable to establish connection to VxCage: %s" % e)  
        
        try:    
            check = json.loads(response_data)
        except ValueError as e:
            raise Exception("Unable to convert response to JSON: %s" % e)
            
        if md5 and check["md5"] == md5:
            log.info("File " + md5 + " is in VxCage")
            return True
        elif sha256 and check["sha256"] == sha256:
            log.info("File " + sha256 + " is in VxCage")
            return True            
        
        return False
