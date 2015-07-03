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

log = logging.getLogger("Processing F-Secure AV")

class FSecure(IPlugin, Processing):

    def run(self, objfile):
        self.key = "AntivirusScanF-Secure"
        self.score = 0
        self.avPath = self.options.get("fsecure_path", None)
        result = {}

        try:
            result["F-Secure"] = self.fsecure(objfile.file.temp_file)
        except (Exception) as e:
            log.error("The module \"F-Secure\" returned the following error: %s" % e)        
   
        return result
    
    def fsecure(self, file_path):
        result = None
                   
        if not self.avPath:
            raise Exception("F-Secure Antivir path is not set in the configuration!")                     
    
        if os.path.isfile(self.avPath):
            try:
                output = subprocess.Popen([self.avPath, '--virus-action1=none', file_path], stdout=subprocess.PIPE).communicate()[0]
                
                
                if "Infected:" in output:
                    self.score = 10

                    rpd = re.compile('\sInfected:\s(.+)', re.IGNORECASE)
                    rpdFind = re.findall(rpd, output)

                    r = ''
                    for r in rpdFind:
                        result = r
                
                elif "Riskware:" in output:
                    self.score = 10

                    rpd = re.compile('\sRiskware:\s(.+)', re.IGNORECASE)
                    rpdFind = re.findall(rpd, output)

                    r = ''
                    for r in rpdFind:
                        result = r
                else:
                    result = 'OK'
            except (Exception) as e:
                raise Exception("F-Secure Antivir scan file '%s' Failed" % e)
            
            log.info(result)
            return result      
