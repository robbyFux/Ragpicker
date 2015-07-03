# Copyright (C) 2013-2015 Ragpicker Developers.
# This file is part of Ragpicker Malware Crawler - http://code.google.com/p/malware-crawler/

import re
import logging
import utils.pefile as pefile
from core.commonutils import getFileTypeFromBuffer
from core.abstracts import Processing



try:
    from yapsy.IPlugin import IPlugin
except ImportError:
    raise ImportError, 'Yapsy (Yet Another Plugin System) is required to run this program : http://yapsy.sourceforge.net'

log = logging.getLogger("PeCarve")

class PeCarve(IPlugin, Processing):

    def run(self, objfile):
        
        try:
            objfile.file.temp_file
            carvedFiles = self.carve(objfile.file.temp_file)
            
            if objfile.unpacked_file:
                carvedFiles = carvedFiles + self.carve(objfile.unpacked_file.temp_file)
            
            for carvedFile in carvedFiles:
                objfile.add_included_file(carvedFile)   
       # except (Exception) as e:
       #     log.error("The module \"PeCarve\" returned the following error: %s" % e)        
        finally:
            pass
            
        return objfile  
    
    def carve(self, filePath):    
        cavedFiles = []
        # read the file into a buffer
        try:
            file = open(filePath, 'rb')
            buffer = file.read()
        except (Exception) as e:
            raise Exception("PeCarve could not access file: %s" % filePath)
            
        # carve out embeddded executables
        # For each address that contains MZ
        for offset in [tmp.start() for tmp in re.finditer('\x4d\x5a', buffer)]:
            file.seek(offset)
            
            # MZ on offset 0x0
            if offset == 0:
                continue
            
            try:
                pe = pefile.PE(data=file.read())
            except:
                # Failed to parse EXE
                continue
          
            log.info('PE found at offset: ' + hex(offset))
            cavedFiles.append(pe.trim())
            
            file.seek(0)
            pe.close()  
        
        return cavedFiles