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

log = logging.getLogger("ClamAvUnpacker")

class ClamAvUnpacker(IPlugin, Processing):
    """ Supported packer: Aspack, UPX, FSG, Petite, PeSpin, NsPack, wwpack32, Mew, Upack, Yoda Cryptor 
    """
    def run(self, objfile):
        self.avPath = self.options.get("clamscan_path", None)
        tmpPath = self.getTmpPath('clamscan_')
        
        try:
            self._unpack(objfile, tmpPath)
        except (Exception) as e:
            log.error("The module \"ClamAvUnpacker\" returned the following error: %s" % e)        
        finally:
            # Delete tmpPath
            shutil.rmtree(tmpPath, ignore_errors=True)
            
        return objfile
    
    def _unpack(self, objfile, temp_path): 
        if not self.avPath:
            raise Exception("ClamAv path is not set in the configuration!")
        
        if os.path.isfile(self.avPath):
            try:
                dummyDB = os.path.join(RAGPICKER_ROOT, 'data', 'clamav_dummy.hdb')
                output = subprocess.Popen([self.avPath, "--debug", "--leave-temps", "--database=" + dummyDB, \
                                           "--tempdir=" + temp_path, objfile.file.temp_file], \
                                          stdout=subprocess.PIPE, stderr=subprocess.STDOUT).communicate()
                                          
                # FSG: Unpacked and rebuilt executable saved in
                # UPX/FSG: Decompressed data saved in 
                # MEW: Unpacked and rebuilt executable saved in
                if " saved in " in output[0]:
                    log.info("File unpacked !!!!")
                    unpackedFile = self._parseUnpacked(output[0])
                    objfile.set_unpacked_file(unpackedFile)
            except (Exception) as e:
                raise Exception("ClamAV _unpack file %s Failed" % e)
    
    def _parseUnpacked(self, data):
        rpd = re.compile('debug:.*saved\sin\s(.+)', re.IGNORECASE)
        rpdFind = re.findall(rpd, data)
        
        for file in rpdFind:
            log.debug(file)
            return file  
