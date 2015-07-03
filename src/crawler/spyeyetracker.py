# Copyright (C) 2013-2015 Ragpicker Developers.
# This file is part of Ragpicker Malware Crawler - http://code.google.com/p/malware-crawler/

import logging

from core.abstracts import Crawler


try:
    from yapsy.IPlugin import IPlugin
except ImportError:
    raise ImportError, 'Yapsy (Yet Another Plugin System) is required to run this program : http://yapsy.sourceforge.net'

log = logging.getLogger("SpyEyetrackerCrawler")

class SpyEyetracker(IPlugin, Crawler):     
    
    def run(self):
        self.mapURL = {}
        log.debug("Fetching from SpyEyetracker RSS")
        
        # parser
        soup = self.parse('https://spyeyetracker.abuse.ch/monitor.php?rssfeed=binaryurls')
        
        for row in soup('description'):
            site = str(row).split()[2].replace(',', '')
            if site != "This":
                self.storeURL(site)
        
        log.info("Found %s urls" % len(self.mapURL))      
            
        return self.mapURL
