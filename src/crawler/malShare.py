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

log = logging.getLogger("MalShareCrawler")
URL_DAILY = "http://www.malshare.com/daily/malshare.current.txt"
URL_GET_FILE = "http://api.malshare.com/sampleshare.php?action=getfile&api_key=%s&hash=%s"

class MalShare(IPlugin, Crawler):
    
    def run(self):
        apikeys = self.options.get("apikey", None)
        # Cycle through these values.
        apikeys = itertools.cycle(apikeys.split(','))
        limit = int(self.options.get("limit", 1000))
        self.mapURL = {}
        log.debug("Fetching from MalShare daily list")
        
        if not apikeys:
            raise Exception("MalShare API key not configured, skip")
        
        for md5_hash in self.pull_daily_list():
            limit -= 1
            if limit >= 0 and md5_hash:
                url = URL_GET_FILE % (apikeys.next(), md5_hash)
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
