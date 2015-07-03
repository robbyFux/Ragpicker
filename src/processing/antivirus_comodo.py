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

log = logging.getLogger("Processing COMODOAv")

class Comodo(IPlugin, Processing):

    def run(self, objfile):
        self.key = "AntivirusScanCOMODO"
        self.score = 0
        self.avPath = self.options.get("comodo_path", None)
        result = {}

        try:
            result["COMODO"] = self.comodo(objfile.file.temp_file)
        except (Exception) as e:
            log.error("The module \"COMODO\" returned the following error: %s" % e)        
   
        return result
    
    def comodo(self, file_path):
        result = None
                   
        if not self.avPath:
            raise Exception("COMODO Antivir path is not set in the configuration!")                     
    
        if os.path.isfile(self.avPath):
            try:
                output = subprocess.Popen([self.avPath, '-vs', file_path], stdout=subprocess.PIPE).communicate()[0]
                
                if not "Number of Found Viruses: 0" in output:
                    self.score = 10

                    rpd = re.compile('\sFound Virus, Malware Name is\s(.+)', re.IGNORECASE)
                    rpdFind = re.findall(rpd, output)

                    r = ''
                    for r in rpdFind:
                        result = r
                else:
                    result = 'OK'
            except (Exception) as e:
                raise Exception("COMODO Antivir scan file '%s' Failed" % e)       
            
            log.info(result)
            return result      
