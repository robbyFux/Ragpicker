# Copyright (C) 2013-2015 Ragpicker Developers.
# This file is part of Ragpicker Malware Crawler - http://code.google.com/p/malware-crawler/

import hashlib
import logging
import os
import re
import tempfile
import urllib2

try:
    from BeautifulSoup import BeautifulSoup as bs
except ImportError:
    raise ImportError, 'Beautiful Soup parser: http://www.crummy.com/software/BeautifulSoup/'

log = logging.getLogger(__name__)

class Processing(object):
    """Base abstract class for Processing-Module."""

    def __init__(self):
        self.options = None
        self.task = None
        
    def set_options(self, options):
        """Set options.
        @param options: options dict.
        """
        self.options = options
        
    def set_task(self, task):
        """Add task information.
        @param task: task dictionary.
        """
        self.task = task           

    def run(self, objfile):
        """Start report processing. 
        @raise NotImplementedError: this method is abstract.
        """
        raise NotImplementedError
    
    # beautifulsoup parser
    def parse(self, url):
        request = urllib2.Request(url)
        request.add_header('User-Agent', 'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1)')
        try:
            http = bs(urllib2.urlopen(request, timeout=30))
        except Exception, e:
            log.error("%s - Error parsing %s" % (e, url))
            return
        return http    
    
    def getTmpPath(self, prefix):
        tmppath = tempfile.gettempdir()
        targetpath = os.path.join(tmppath, "ragpicker-tmp")
        if not os.path.exists(targetpath):
            os.mkdir(targetpath)
            
        tempPath = tempfile.mkdtemp(prefix=prefix, dir=targetpath)    
            
        log.debug("tempPath=%s" % tempPath)
        return tempPath     
    
class Report(object):
    """Base abstract class for reporting module."""
    order = 1

    def __init__(self):
        self.options = None
        self.task = None
        
    def set_task(self, task):
        """Add task information.
        @param task: task dictionary.
        """
        self.task = task              

    def set_options(self, options):
        """Set report options.
        @param options: report options dict.
        """
        self.options = options

    def run(self, results, objfile):
        """Start report processing.
        @param results: results dict.
        @param objfile: file object
        @raise NotImplementedError: this method is abstract.
        """
        raise NotImplementedError
    
    def delete(self, sha256):
        """Delete Malware-Sample Report by SHA256-Hash
        @param sha256: Hash from Malware-Sample
        @raise NotImplementedError: this method is abstract.
        """
        pass
    
    def deleteAll(self):
        """Delete all Reports
        @raise NotImplementedError: this method is abstract.
        """
        pass
    
    def export(self, sha256):
        """Export Malware-Sample Report by SHA256-Hash
        @param sha256: Hash from Malware-Sample
        @raise NotImplementedError: this method is abstract.
        """
        pass

class Crawler(object):
    """Base abstract class for Malware Crawler."""
            
    def __init__(self):
        self.options = None            
        
    def set_options(self, options):
        """Set report options.
        @param options: report options dict.
        """
        self.options = options
        
    # TODO session zum Download in der Map speichern (Login)
    def storeURL(self, url):
        try:
            if not re.match('http', url):
                url = 'http://' + url
            
            md5 = hashlib.md5(url).hexdigest()
            self.mapURL[md5] = url      
        except Exception as e:
            log.error('Error in storeURL: %s', e) 
            
    def run(self):
        """Start report processing. 
        @return: Returns a Map of URL-MD5 Hash and HTTP-URLs
        @raise NotImplementedError: this method is abstract.
        """
        raise NotImplementedError    
    
    # beautifulsoup parser
    def parse(self, url):
        request = urllib2.Request(url)
        request.add_header('User-Agent', 'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1)')
        try:
            http = bs(urllib2.urlopen(request, timeout=120))
        except Exception, e:
            log.error("%s - Error parsing %s" % (e, url))
            return
        return http 
