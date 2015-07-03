# Copyright (C) 2013-2015 Ragpicker Developers.
# This file is part of Ragpicker Malware Crawler - http://code.google.com/p/malware-crawler/

import logging

from core.abstracts import Processing
import core.commonutils as commonutils


try:
    from yapsy.IPlugin import IPlugin
except ImportError:
    raise ImportError, 'Yapsy (Yet Another Plugin System) is required to run this program : http://yapsy.sourceforge.net'

log = logging.getLogger("ProcessingYara")

class Yara(IPlugin, Processing):

    def run(self, objfile):
        self.key = "Yara"
        self.score = 0
        rulepath = self.options.get("rulepath")
        results = []
        resultOrginalFile = commonutils.processYara(rulepath, filepath=objfile.file.temp_file) 
        
        # Run YARA for unpacked file
        if objfile.unpacked_file:
            resultUnpackedFile = commonutils.processYara(rulepath, filepath=objfile.unpacked_file.temp_file, 
                                                         prefix="UnpackedFile") 
            
            # Update Meta-description -> set marker UnpackedFile
            for res in resultUnpackedFile:
                desc = res.get("meta").get("description")
                desc = "UnpackedFile - %s" % desc
                res["meta"]["description"] = desc
                results.append(res)
            
        results = results + resultOrginalFile  
            
        return results
