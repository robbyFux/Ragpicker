# Copyright (C) 2013-2015 Ragpicker Developers.
# This file is part of Ragpicker Malware Crawler - http://code.google.com/p/malware-crawler/

import httplib2
import logging
import re
import urllib
import urllib2

from core.abstracts import Processing
from core.commonutils import convertDirtyDict2ASCII


try:
    from yapsy.IPlugin import IPlugin
except ImportError:
    raise ImportError, 'Yapsy (Yet Another Plugin System) is required to run this program : http://yapsy.sourceforge.net'

MALICIOUS = "Malicious"
log = logging.getLogger("ProcessingInetSourceAnalysis")

class InetSourceAnalysis(IPlugin, Processing):
    
    def run(self, objfile):
        self.key = "InetSourceAnalysis"
        self.score = -1
        self.hitcount = 0
        self.is_urlvoid = self.options.get("urlvoid", False)
        self.is_fortiguard = self.options.get("fortiguard", False)
        self.is_urlquery = self.options.get("urlquery", False)
        self.is_ipvoid = self.options.get("ipvoid", False)
        self.whitelist = self.options.get("whitelist", None)
        
        # IP-Adressen fuer weitere Analyse
        self.ip = []
        # Dictionary containing all the results of this processing.
        self.results = {}   
        
        input = objfile.get_url_hostname()
        
        # Check whether an analysis should be performed
        if objfile.get_url_protocol() != "file" or not self._isWhitelist(input):
            # no analysis
            return 
        
        rpIP = re.compile('\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', re.IGNORECASE)
        rpdFindIP = re.findall(rpIP, input)
        rpdSortedIP = sorted(rpdFindIP)
        rpdSortedIP = str(rpdSortedIP)
        rpdSortedIP = rpdSortedIP[2:-2]
        
        if rpIP == input:
            log.debug('%s is an IP.' % input)
            self._processIP(input)
        else:
            log.debug('%s is a URL.' % input)
            self._processDomain(input)
            
        # calculate scoring
        self.score = self.hitcount * 2
        
        return self.results
    
    def _isWhitelist(self, hostname):
        if hostname and self.whitelist and hostname in self.whitelist:
            log.info("%s in domain whitelist: %s" % (hostname, self.whitelist))
            return True
        
        return False
    
    def _processIP(self, ip):
        if self.is_ipvoid:
            try:
                ipvoid = self._ipVoid(ip)   
                self.results["IPVoid"] = ipvoid   
            except Exception as e:
                log.error("Service IPVoid Failed: %s" % e)          

    def _processDomain(self, url):

        if self.is_fortiguard:
            try:
                fortiGuard = self._fortiURL(url)
                self.results["FortiGuard"] = fortiGuard
            except Exception as e:
                log.error("Service FortiGuard Failed: %s" % e)
        
        if self.is_urlvoid:
            try:
                urlvoid = self._urlVoid(url)
                self.results["URLVoid"] = urlvoid
            except Exception as e:
                log.error("Service URLVoid Failed: %s" % e)
        
        if self.is_urlquery:
            try:
                urlquery = self._urlQuery(url)
                self.results["URLQuery"] = urlquery
            except Exception as e:
                log.error("Service URLQuery Failed: %s" % e)
        
        for ip in self.ip:
            self._processIP(ip)
            
    def _urlQuery(self, urlInput):
        httplib2.debuglevel = 4          
        
        url = "http://urlquery.net/%s"
        action_search = url % "search.php?q=%s" % urlInput
        
        conn = urllib2.urlopen(action_search, timeout=60)
        content2String = conn.read()      

        rpd = re.compile('.*&nbsp;&nbsp;0\sresults\sreturned*', re.IGNORECASE)
        rpdFind = re.findall(rpd, content2String)
    
        if not rpdFind:
            # Reports found
            log.debug('urlquery Reports found')
            self.hitcount += 1
            urlqueryResults = []
            
            rpd = re.compile("\shref='(.*?)'\>", re.IGNORECASE)
            rpdFindReport = re.findall(rpd, content2String)
            
            rpd = re.compile("\<td\>\<a\stitle='(.*?)'\shref='report.php", re.IGNORECASE)
            rpdFindReportUrl = re.findall(rpd, content2String)               
            
            rpd = re.compile("\<td\salign='center'\>\<b\>(.*?)\<\/b\>\<\/td\>", re.IGNORECASE)
            rpdFindAlertsIDS = re.findall(rpd, content2String)    
            
            rpd = re.compile("\<td\>\<nobr\>\<center\>(.*?)\<\/center\>\<\/nobr\>\<\/td\>", re.IGNORECASE)
            rpdFindDatum = re.findall(rpd, content2String)    
            
            rpd = re.compile("align='left'\stitle='(.*?)'\swidth='\d{2}'\sheight='\d{2}'\s/>", re.IGNORECASE)
            rpdFindLand = re.findall(rpd, content2String)   
        
            i = 0
            datum = ''
            for datum in rpdFindDatum:   
                result = {} 
                result["datum"] = datum    
                result["alerts_ids"] = rpdFindAlertsIDS[i]
                result["country"] = rpdFindLand[i]
                result["reportUrl"] = convertDirtyDict2ASCII(rpdFindReportUrl[i])
                result["report"] = url % rpdFindReport[i]   
                urlqueryResults.append(result)                   
                i += 1             

            urlquery = {'url':urlInput, 'urlResult':urlqueryResults}
        else:   
            log.debug('urlquery Reports NOT found')  
            urlquery = {'url': urlInput, 'urlResult' : 'NOT listed'}     
            
        return urlquery
    
    def _fortiURL(self, urlInput): 
        httplib2.debuglevel = 4          
        
        conn = urllib2.urlopen("http://www.fortiguard.com/ip_rep.php?data=" + urlInput + "&lookup=Lookup", timeout=60)
        content2String = conn.read()        
        
        rpd = re.compile('h3\sstyle\=\"float:\sleft\"\>Category:\s(.+)\<\/h3', re.IGNORECASE)
        rpdFind = re.findall(rpd, content2String)
        rpdSorted = rpdFind

        m = ''
        for m in rpdSorted:
            fortiGuard = urlInput + " Categorization: " + m  
            
            if MALICIOUS in m:
                self.hitcount += 1
        if m == '':
            fortiGuard = urlInput + " Categorization: Uncategorized"   
            
        return fortiGuard

    def _urlVoid(self, urlInput):    
        httplib2.debuglevel = 4 
        conn = urllib2.urlopen("http://urlvoid.com/scan/" + urlInput, timeout=60)
        content2String = conn.read()            
        
        rpderr = re.compile('An\sError\soccurred', re.IGNORECASE)
        rpdFinderr = re.findall(rpderr, content2String)
        
        if "ERROR" in str(rpdFinderr):
            _urlvoid = ('http://www.urlvoid.com/')
            raw_params = {'url':urlInput, 'Check':'Submit'}
            params = urllib.urlencode(raw_params)
            request = urllib2.Request(_urlvoid, params, headers={'Content-type':'application/x-www-form-urlencoded'})
            page = urllib2.urlopen(request, timeout=60)
            page = page.read()
            content2String = str(page)
   
        rpd = re.compile('title=\"Find\swebsites\shosted\shere\"\><strong\>(\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}).+', re.IGNORECASE)
        rpdFind = re.findall(rpd, content2String)
        rpdSortedIP = rpdFind 
        
        rpd = re.compile('alt=\"Alert\"\s\/>.{9}<a.rel=\"nofollow\"\shref="(.{6,200})\"\stitle', re.IGNORECASE)
        rpdFind = re.findall(rpd, content2String)
        rpdSortBlacklist = rpdFind  
        
        rpd = re.compile('alt\=\"flag\".+\>(.+)\<\/td\>', re.IGNORECASE)
        rpdFind = re.findall(rpd, content2String)
        rpdSortCountry = rpdFind
        
        rpd = re.compile('HTTP\sStatus\sCode<\/td\>\<td\>(.+)\<\/td\>\<\/tr\>', re.IGNORECASE)
        rpdFind = re.findall(rpd, content2String)
        rpdSortHTTPResponseCode = rpdFind
        
        rpd = re.compile('\<span\sclass=\"label label-danger\"\>(.+)\<\/span\>', re.IGNORECASE)
        rpdFind = re.findall(rpd, content2String)
        rpdSortWebsiteStatus = rpdFind             
        
        urlResult = {}
        
        if rpdSortedIP:
            urlResult["IP"] = rpdSortedIP[0]
            # IP fuer weitere Analyse Speichern
            self.ip.append(rpdSortedIP[0])
        
        if rpdSortCountry:
            urlResult["CountryCode"] = rpdSortCountry[0].strip()
        else:
            urlResult["CountryCode"] = "No Country listed"
            
        if rpdSortHTTPResponseCode:
            urlResult["HTTPResponseCode"] = rpdSortHTTPResponseCode[0]
        else:
            urlResult["HTTPResponseCode"] = 'HTTP-Response-Code not listed.'
        
        if rpdSortWebsiteStatus:
            urlResult["BlacklistStatus"] = rpdSortWebsiteStatus[0]
            # URL blacklisted
            self.hitcount += 1
            
            blacklist = []
            for j in rpdSortBlacklist:
                blacklist.append({"Blacklist" : 'Host is listed in blacklist at: ' + j})
                self.hitcount += 1
                
            if blacklist:
                urlResult["Blacklists"] = blacklist
        else:
            urlResult["BlacklistStatus"] = 'The website is not blacklisted.'       

        return {"url" : urlInput, "urlResult" : urlResult}
        
    def _ipVoid(self, ipInput):
        httplib2.debuglevel = 4     
        
        conn = urllib2.urlopen("http://ipvoid.com/scan/" + ipInput, timeout=60)
        content2String = conn.read()        
        
        rpNotFound = re.compile('<h1>Report\snot\sfound<\/h1>', re.IGNORECASE)
        rpdFindNotFound = re.findall(rpNotFound, content2String)
        
        # Report not found -> exit
        if rpdFindNotFound:
            log.info("ipvoid.com: Report not found")
            return {"ip" : ipInput, "ipResult" : {"BlacklistStatus":"Report not found"}} 
              
        rpd = re.compile('title="Detected"\s\/>\s&nbsp;\s<a.rel=\"nofollow\"\shref="(.{6,200})\"\stitle', re.IGNORECASE)
        rpdFind = re.findall(rpd, content2String)
        rpdSortBlacklist = rpdFind
        
        rpd = re.compile('label-.*\">(.+)\<\/span\>\<\/td\>\<\/tr\>', re.IGNORECASE)
        rpdFind = re.findall(rpd, content2String)
        rpdSortBlacklistStatus = rpdFind        
    
        rpd = re.compile('<tr><td>ISP<\/td><td>(.+)<\/td\>\<\/tr\>', re.IGNORECASE)
        rpdFind = re.findall(rpd, content2String)
        rpdSortISP = rpdFind
    
        rpd = re.compile('Country\sCode</td><td><img.+alt="Flag"\s\/>.(.+)<\/td\>\<\/tr\>', re.IGNORECASE)
        rpdFind = re.findall(rpd, content2String)
        rpdSortCountry = rpdFind

        ipResult = {}
        
        if "BLACKLISTED" in rpdSortBlacklistStatus[0]:
            ipResult["BlacklistStatus"] = rpdSortBlacklistStatus[0]
            self.hitcount += 1
            
            blacklist = []
            for j in rpdSortBlacklist:
                blacklist.append({"Blacklist" : 'IP is listed in blacklist at: ' + j})
                self.hitcount += 1
                
            if blacklist:
                ipResult["Blacklists"] = blacklist            
        else:
            ipResult["BlacklistStatus"] = rpdSortBlacklistStatus[0]   
       
        if rpdSortISP:
            ipResult["ISP"] = rpdSortISP[0]
        else:
            ipResult["ISP"] = 'No ISP listed'
        
        if rpdSortCountry:
            ipResult["CountryCode"] = rpdSortCountry[0].strip()
        else:
            ipResult["CountryCode"] = "No Country listed"      

        return {"ip" : ipInput, "ipResult" : ipResult}     
            
    def _checkIP(self, ipAdress):
        # ToDo in config auslagern
        if len(ipAdress) > 0 and ipAdress.find("192.168.") == -1 and ipAdress.find("8.8.8.8") == -1:
            return True
        
    def _isInURLVoid(self, ipAdress):
        for obj in self.ip:
            if ipAdress == obj:
                return True
        return False
