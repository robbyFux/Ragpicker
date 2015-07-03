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

log = logging.getLogger("ProcessingAvgAv")

class Avg(IPlugin, Processing):

    def run(self, objfile):
        self.key = "AntivirusScanAvg"
        self.score = 0
        self.avPath = self.options.get("avg_path", None)
        result = {}

        try:
            result["Avg"] = self.avg(objfile.file.temp_file)
        except (Exception) as e:
            log.error("The module \"Avg\" returned the following error: %s" % e)        
   
        return result
    
    def avg(self, file_path):
        result = None
                   
        if not self.avPath:
            raise Exception("AvgAV path is not set in the configuration!")                     
    
        if os.path.isfile(self.avPath):
            try:
                output = subprocess.Popen([self.avPath, '-w', '-m', '-a', file_path], stdout=subprocess.PIPE).communicate()[0]
                
                if not "Infections found  :  0(0)" in output:
                    self.score = 10
                    result = output.split('\n')[6].split('  ')[1]
                else:
                    result = 'OK'
            except (Exception) as e:
                raise Exception("Avg-Antivir scan file '%s' Failed" % e)       
            
            return result      
