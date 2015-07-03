# Copyright (C) 2013-2015 Ragpicker Developers.
# This file is part of Ragpicker Malware Crawler - http://code.google.com/p/malware-crawler/

import logging
import re

from core.abstracts import Crawler


try:
    from yapsy.IPlugin import IPlugin
except ImportError:
    raise ImportError, 'Yapsy (Yet Another Plugin System) is required to run this program : http://yapsy.sourceforge.net'

log = logging.getLogger("Malc0deCrawler")

class Malc0de(IPlugin, Crawler):
     
    def run(self):
        self.mapURL = {} 
        mlc = []
        log.debug("Fetching from Malc0de RSS")
        
        # parser
        soup = self.parse('http://malc0de.com/rss')
        
        for row in soup('description'):
            mlc.append(row)
        del mlc[0]
        
        for row in mlc:
            site = re.sub('&amp;', '&', str(row).split()[1]).replace(',', '')
            self.storeURL(site) 
            
        log.info("Found %s urls" % len(self.mapURL))       
            
        return self.mapURL
