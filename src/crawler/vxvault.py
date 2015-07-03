# Copyright (C) 2013-2015 Ragpicker Developers.
# This file is part of Ragpicker Malware Crawler - http://code.google.com/p/malware-crawler/

import logging

from core.abstracts import Crawler


try:
    from yapsy.IPlugin import IPlugin
except ImportError:
    raise ImportError, 'Yapsy (Yet Another Plugin System) is required to run this program : http://yapsy.sourceforge.net'

log = logging.getLogger("VxvaultCrawler")

class Vxvault(IPlugin, Crawler):      
    
    def run(self):
        self.mapURL = {}
        log.debug("Fetching from VXVault List")
        
        # parser
        soup = self.parse('http://vxvault.siri-urz.net/URL_List.php')
        
        vxv = []
        
        for row in soup('pre'):
            vxv = row.string.split('\r\n')
        del vxv[:4]
        del vxv[-1]
        log.info("Found %s urls" % len(vxv))
        for row in vxv:
            self.storeURL(row)          
            
        return self.mapURL
