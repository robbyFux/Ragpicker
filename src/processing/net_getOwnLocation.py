# Copyright (C) 2013-2015 Ragpicker Developers.
# This file is part of Ragpicker Malware Crawler - http://code.google.com/p/malware-crawler/

import logging
import re
import socket

from core.abstracts import Processing
import core.commonutils as commonutils


try:
    from BeautifulSoup import BeautifulSoup as bs
except ImportError:
    raise ImportError, 'Beautiful Soup parser: http://www.crummy.com/software/BeautifulSoup/'

try:
    from yapsy.IPlugin import IPlugin
except ImportError:
    raise ImportError, 'Yapsy (Yet Another Plugin System) is required to run this program : http://yapsy.sourceforge.net'

log = logging.getLogger("ProcessingGetOwnLocations")

class getOwnLocation(IPlugin, Processing):
    
    def run(self, objfile):
        self.key = "OwnLocation"
        self.score = -1
        
        result = self.wieistmeineip()
        return result
    
    def wieistmeineip(self):
        result = {}
        # Save original socket
        originalSocket = socket.socket
        # Set TOR Socks proxy
        commonutils.setTorProxy()
        
        try: 
            # Load 
            soup = self.parse("http://www.wieistmeineip.de")
            location = soup.findAll("div", { "class" : "location" })[0]
            location = bs(location.text, convertEntities=bs.HTML_ENTITIES)
            
            ip = soup.findAll('div', id='ipv4')[0]
            raw_ip = bs(ip.text, convertEntities=bs.HTML_ENTITIES)
            pattern = re.compile('[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}')
            ip = re.search(pattern, raw_ip.text)    
            
            result["ipaddress"] = ip.group(0)
            result["country"] = str(location)
        finally:
            # Removing SOCKS Tor Proxy 
            socket.socket = originalSocket 
            
        return result
    
