# Copyright (C) 2013-2015 Ragpicker Developers.
# This file is part of Ragpicker Malware Crawler - http://code.google.com/p/malware-crawler/

import logging
import os
import re
import shutil
import subprocess

from core.abstracts import Processing
from core.constants import RAGPICKER_ROOT


try:
    from yapsy.IPlugin import IPlugin
except ImportError:
    raise ImportError, 'Yapsy (Yet Another Plugin System) is required to run this program : http://yapsy.sourceforge.net'

log = logging.getLogger("ExtractOffice")

class ExtractOffice(IPlugin, Processing):

    def run(self, objfile):
        wine = self.options.get("wine", "/usr/bin/wine")
        brute = self.options.get("brute", True)
        tmpPath = self.getTmpPath("extractOffice_")
        
        try:
            officeFile = os.path.join(tmpPath, "temp.file")
            # Copy TempFile > new TempDir
            shutil.copyfile(objfile.file.temp_file, officeFile)
            scanner = None
            option = None
            
            if objfile.file.get_type() == "Composite":
                scanner = os.path.join(RAGPICKER_ROOT, 'utils', 'OfficeMalScanner', 'OfficeMalScanner.exe')
                option = "' scan"
                if brute:
                    option = option + " brute" 
            elif objfile.file.get_type() == "Rich":
                scanner = os.path.join(RAGPICKER_ROOT, 'utils', 'OfficeMalScanner', 'RTFScan.exe')
                option = "' scan"
                
            cmd = wine + " " + scanner + " '" + officeFile + option
            log.debug(cmd)
            self.officeScanExe(cmd, tmpPath, objfile)

        except (Exception) as e:
            log.error("The module \"ExtractOffice\" returned the following error: %s" % e)        
        finally:
            # Delete tmpPath
            shutil.rmtree(tmpPath, ignore_errors=True)
        
        return objfile
    
    def officeScanExe(self, cmd, tmpPath, objfile):
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, cwd=tmpPath, shell=True)
        (stdout, stderr) = process.communicate()
        
        stdout = stdout.decode('utf-8', 'ignore')
        
        if stdout:
            if "unencrypted MZ/PE signature found" in stdout:
                log.info("MZ/PE File unpacked !!!!")
                unpackedFile = self._parseUnpacked(stdout)
                log.info("OLEScan = " + unpackedFile)
                objfile.set_unpacked_file(os.path.join(tmpPath, str(unpackedFile).strip()))
        else: 
            raise Exception(stderr)
    
    def _parseUnpacked(self, data):
        rpd = re.compile('Dumping Memory to disk as filename:\s(.+)', re.IGNORECASE)
        rpdFind = re.findall(rpd, data)
        
        for file in rpdFind:
            log.debug(file)
            return file  
