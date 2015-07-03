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

log = logging.getLogger("ProcessingAviraAv")

class Avira(IPlugin, Processing):

    def run(self, objfile):
        self.key = "AntivirusScanAvira"
        self.score = 0
        self.avPath = self.options.get("avira_path", None)
        self.aviraHeurLevel = self.options.get("avira_heur_level", None)
        result = {}

        try:
            result["Avira"] = self.avira(objfile.file.temp_file)
        except (Exception) as e:
            log.error("The module \"Avira\" returned the following error: %s" % e)        
   
        return result
    
    def avira(self, file_path):
        # Dictionary containing all the results of this processing.
        results = {}   
        resultFund = None
        resultUrl = None
                   
        if not self.avPath:
            raise Exception("AviraAV path is not set in the configuration!")                   
                   
        if self.aviraHeurLevel and (self.aviraHeurLevel < 0 and self.aviraHeurLevel > 3):
            self.aviraHeurLevel = 3   
    
        quarantineDir = self.options.get("quarantine-dir", "/tmp/")
    
        if os.path.isfile(self.avPath):
            try:
                output = subprocess.Popen([self.avPath, '--batch', '--scan-mode=all', \
                                           '--heur-macro=yes', '--heur-level=' + str(self.aviraHeurLevel), \
                                           '--quarantine-dir=' + quarantineDir,
                                           file_path], stdout=subprocess.PIPE).communicate()[0]
                
                rpd = re.compile('\sFUND:\s(.+)', re.IGNORECASE)
                rpdFind = re.findall(rpd, output)
                rpdSorted = sorted(rpdFind)                
    
                r = ''
                for r in rpdSorted:
                    resultFund = r
                    
                if r == '':
                    resultFund = 'OK'
                else:
                    # Fund AV-Hit
                    self.score = 10
                    rpd = re.compile('\sFUND-URL:\s(.+)', re.IGNORECASE)
                    rpdFind = re.findall(rpd, output)
                    rpdSorted = sorted(rpdFind)
    
                r = ''
                for r in rpdSorted:
                    resultUrl = r
                    
                results["scan"] = resultFund
                
                if resultUrl:
                    results["url"] = resultUrl
                                    
            except (Exception) as e:
                raise Exception("Avira-Antivir scan file '%s' Failed" % e)       
            
            return results      
