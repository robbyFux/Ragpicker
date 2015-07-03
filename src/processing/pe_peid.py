# Copyright (C) 2013-2015 Ragpicker Developers.
# This file is part of Ragpicker Malware Crawler - http://code.google.com/p/malware-crawler/

import logging
import os

from core.abstracts import Processing
from core.constants import RAGPICKER_ROOT
from utils.pefile import PE
from utils.pefile import PEFormatError
from utils.peutils import SignatureDatabase


try:
    from yapsy.IPlugin import IPlugin
except ImportError:
    raise ImportError, 'Yapsy (Yet Another Plugin System) is required to run this program : http://yapsy.sourceforge.net'

log = logging.getLogger("ProcessingPEID")

class PEID(IPlugin, Processing):
    
    def run(self, objfile):
        """Gets PEID signatures.
        @return: matched signatures or None.
        """
        self.key = "PEID"
        self.score = -1
        
        try:
            pe = PE(data=objfile.file.file_data)
            signatures = SignatureDatabase(os.path.join(RAGPICKER_ROOT, 'data', 'peiddb.txt'))
            match = signatures.match(pe, ep_only=True)
            if match:
                log.info("PEID match: %s" % match)
                self.score = 10
            return match
        except PEFormatError, e:
            log.warn("Error - No Portable Executable: %s" % e)        
        
        return None
