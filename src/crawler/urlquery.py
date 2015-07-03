# Copyright (C) 2013-2015 Ragpicker Developers.
# This file is part of Ragpicker Malware Crawler - http://code.google.com/p/malware-crawler/

import logging
import re

from core.abstracts import Crawler


try:
    from yapsy.IPlugin import IPlugin
except ImportError:
    raise ImportError, 'Yapsy (Yet Another Plugin System) is required to run this program : http://yapsy.sourceforge.net'

log = logging.getLogger("UrlQueryCrawler")

class UrlQuery(IPlugin, Crawler):     
    
    def run(self):
        self.mapURL = {}
        log.debug("Fetching from UrlQuery")
        
        # parser
        soup = self.parse('http://urlquery.net')
        
        for t in soup("table", { "class" : "test" }):
            for a in t("a"):
                self.storeURL('http://' + re.sub('&amp;', '&', a.text))        
            
        log.info("Found %s urls" % len(self.mapURL))      
            
        return self.mapURL