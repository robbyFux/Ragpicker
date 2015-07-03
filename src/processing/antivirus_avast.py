# Copyright (C) 2013-2015 Ragpicker Developers.
# This file is part of Ragpicker Malware Crawler - http://code.google.com/p/malware-crawler/

import logging
import os
import re
import subprocess

from core.abstracts import Processing


try:
    from yapsy.IPlugin import IPlugin
except ImportError:
    raise ImportError, 'Yapsy (Yet Another Plugin System) is required to run this program : http://yapsy.sourceforge.net'

log = logging.getLogger("Processing avast Antivirus")

class Avast(IPlugin, Processing):

    def run(self, objfile):
        self.key = "AntivirusScanAvast"
        self.score = 0
        self.avPath = self.options.get("avast_path", None)
        result = {}

        try:
            result["avast"] = self.avast(objfile.file.temp_file)
        except (Exception) as e:
            log.error("The module \"avast\" returned the following error: %s" % e)        
   
        return result
    
    def avast(self, file_path):
        result = None
                   
        if not self.avPath:
            raise Exception("avast Antivir path is not set in the configuration!")                     
    
        if os.path.isfile(self.avPath):
            try:
                output = subprocess.Popen([self.avPath, '-a', file_path], stdout=subprocess.PIPE).communicate()[0]
                
                if not "[OK]" in output:
                    self.score = 10
                    rpd = re.compile('\[infected by:\s(.+)]', re.IGNORECASE)
                    rpdFind = re.findall(rpd, output)

                    r = ''
                    for r in rpdFind:
                        result = r
                else:
                    result = 'OK'
            except (Exception) as e:
                raise Exception("avast Antivir scan file '%s' Failed" % e)       
            
            log.info(result)
            
            return result      
