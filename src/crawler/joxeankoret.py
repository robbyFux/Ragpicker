# Copyright (C) 2014 Ragpicker Developers.
# This file is part of Ragpicker Malware Crawler - http://code.google.com/p/malware-crawler/

import itertools
import logging
import urllib2

from core.abstracts import Crawler

try:
    from yapsy.IPlugin import IPlugin
except ImportError:
    raise ImportError, 'Yapsy (Yet Another Plugin System) is required to run this program : http://yapsy.sourceforge.net'

log = logging.getLogger("JoxeanKoretCrawler")
URL_DAILY = "http://malwareurls.joxeankoret.com/normal.txt"

class JoxeanKoret(IPlugin, Crawler):
    
    def run(self):
        self.mapURL = {}
        log.debug("Fetching from JoxeanKoret daily list")
        
        for url in self.pull_daily_list():
            self.storeURL(url)       

        log.info("Found %s urls" % len(self.mapURL))

        return self.mapURL
    
    def pull_daily_list(self):
        try:
            request = urllib2.Request(URL_DAILY)
            data = urllib2.urlopen(request, timeout=60)
            for line in data.readlines():
                yield line
        except Exception as e:
            log.error("Problem connecting to pull the daily list.")
