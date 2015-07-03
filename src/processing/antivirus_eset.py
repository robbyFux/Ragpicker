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

log = logging.getLogger("Processing ESET Antivir")

class Eset(IPlugin, Processing):

    def run(self, objfile):
        self.key = "AntivirusScanESET"
        self.score = 0
        self.avPath = self.options.get("eset_path", None)
        result = {}

        try:
            result["ESET"] = self.eset(objfile.file.temp_file)
        except (Exception) as e:
            log.error("The module \"ESET\" returned the following error: %s" % e)        
   
        return result
    
    def eset(self, file_path):
        result = None
                   
        if not self.avPath:
            raise Exception("ESET Antivir path is not set in the configuration!")                     
    
        if os.path.isfile(self.avPath):
            try:
                output = subprocess.Popen([self.avPath, '--clean-mode=none', file_path], stdout=subprocess.PIPE).communicate()[0]
                
                if (("threat=" in output) and (not 'threat=""' in output)):
                    self.score = 10
                    rpd = re.compile('\sthreat=\"(.+)\",\saction=', re.IGNORECASE)
                    rpdFind = re.findall(rpd, output)

                    r = ''
                    for r in rpdFind:
                        result = r
                else:
                    result = 'OK'
                     
            except (Exception) as e:
                raise Exception("ESET Antivir scan file '%s' Failed" % e)       
            
            log.info(result)
            
            return result      
