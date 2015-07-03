# Copyright (C) 2013-2015 Ragpicker Developers.
# This file is part of Ragpicker Malware Crawler - http://code.google.com/p/malware-crawler/

import logging
import os
import subprocess

from core.abstracts import Processing


try:
    from yapsy.IPlugin import IPlugin
except ImportError:
    raise ImportError, 'Yapsy (Yet Another Plugin System) is required to run this program : http://yapsy.sourceforge.net'

log = logging.getLogger("ProcessingClamAv")

class ClamAv(IPlugin, Processing):

    def run(self, objfile):
        self.key = "AntivirusScanClamAv"
        self.score = 0
        self.avPath = self.options.get("clamscan_path", None)
        result = {}

        try:
            result["ClamAv"] = self.clamav(objfile.file.temp_file)
        except (Exception) as e:
            log.error("The module \"ClamAv\" returned the following error: %s" % e)        
        
        return result
    
    def clamav(self, file_path): 
        result = None
        
        if not self.avPath:
            raise Exception("ClamAv path is not set in the configuration!")
        
        if os.path.isfile(self.avPath):
            try:
                output = subprocess.Popen([self.avPath, "--no-summary", file_path], \
                                          stdout=subprocess.PIPE).communicate()[0]
                result = output.split('\n')[0].split(':')[1]
                
                if not "OK" in result:
                    self.score = 10
            except (Exception) as e:
                raise Exception("ClamAV scan file %s Failed" % e)
        return result      
