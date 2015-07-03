# Copyright (C) 2013-2015 Ragpicker Developers.
# This file is part of Ragpicker Malware Crawler - http://code.google.com/p/malware-crawler/

import json
import logging
import urllib2

from core.abstracts import Processing
from utils.multiPartForm import MultiPartForm


try:
    from yapsy.IPlugin import IPlugin
except ImportError:
    raise ImportError, 'Yapsy (Yet Another Plugin System) is required to run this program : http://yapsy.sourceforge.net'

log = logging.getLogger("ProcessingCuckooSandbox")

CUCKOO_TASK_CREATE_URL = "http://%s:%s/tasks/create/file "

class CuckooSandbox(IPlugin, Processing):
    
    def run(self, objfile):
        self.key = "CuckooSandbox"
        self.score = -1
        self.host = self.options.get("host")
        self.port = self.options.get("port")
        reponsejson = {}
        
        if not self.host or not self.port:
            raise Exception("Cuckoo REST API server not configurated")
        
        file_extension = '.' + objfile.file.file_extension()
        fileName = objfile.file.get_fileMd5() + file_extension
        rawFile = open(objfile.file.temp_file, 'rb')
        
        log.debug(CUCKOO_TASK_CREATE_URL % (self.host, self.port) + " file=" + fileName)
        
        try:                
            form = MultiPartForm()
            form.add_file('file', fileName, fileHandle=rawFile)
            
            request = urllib2.Request(CUCKOO_TASK_CREATE_URL % (self.host, self.port))
            request.add_header('User-agent', 'Ragpicker')
            body = str(form)
            request.add_header('Content-type', form.get_content_type())
            request.add_header('Content-length', len(body))
            request.add_data(body)
            
            data = urllib2.urlopen(request, timeout=60).read() 
            reponsejson = json.loads(data)
            log.info("Submitted to cuckoo, task ID %s", reponsejson["task_id"])               
        except urllib2.URLError as e:
            raise Exception("Unable to establish connection to Cuckoo REST API server: %s" % e)
        except urllib2.HTTPError as e:
            raise Exception("Unable to perform HTTP request to Cuckoo REST API server (http code=%s)" % e) 
        except ValueError as e:
            raise Exception("Unable to convert response to JSON: %s" % e)
        
        return reponsejson
