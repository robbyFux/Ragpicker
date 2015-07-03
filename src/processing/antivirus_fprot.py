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

log = logging.getLogger("ProcessingFProtAv")

class FProt(IPlugin, Processing):

    def run(self, objfile):
        self.key = "AntivirusScanFProt"
        self.score = 0
        self.avPath = self.options.get("fprot_path", None)
        result = {}

        try:
            result["FProt"] = self.fprot(objfile.file.temp_file)
        except (Exception) as e:
            log.error("The module \"F-Prot\" returned the following error: %s" % e)        
   
        return result
    
    def fprot(self, file_path):
        result = None
                   
        if not self.avPath:
            raise Exception("F-Prot Antivir path is not set in the configuration!")                     
    
        if os.path.isfile(self.avPath):
            try:
                output = subprocess.Popen([self.avPath, '-r', '-f', '--scanlevel=4', '--heurlevel=4', '--adware', '--applications',
                                           file_path], stdout=subprocess.PIPE).communicate()[0]
                
                if not "Infected files: 0" in output:
                    self.score = 10

                    rpd = re.compile('\[Found\s.*\]\s<(.+)>\s\s', re.IGNORECASE)
                    rpdFind = re.findall(rpd, output)

                    r = ''
                    for r in rpdFind:
                        result = r
                else:
                    result = 'OK'
            except (Exception) as e:
                raise Exception("F-Prot-Antivir scan file '%s' Failed" % e)       
            
            log.info(result)
            return result      
