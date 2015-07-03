# Copyright (C) 2013-2015 Ragpicker Developers.
# This file is part of Ragpicker Malware Crawler - http://code.google.com/p/malware-crawler/

import re
import random
import logging

from core.abstracts import Processing

try:
    import requests
except ImportError:
    raise ImportError, 'requests is required to run this program: http://docs.python-requests.org/en/latest/'

try:
    from yapsy.IPlugin import IPlugin
except ImportError:
    raise ImportError, 'Yapsy (Yet Another Plugin System) is required to run this program: http://yapsy.sourceforge.net'

log = logging.getLogger("ProcessingVirusTotal")

VIRUSTOTAL_URL = 'https://www.virustotal.com/vtapi/v2/file/report'

TRENNER = [".", ":", "-", "~", "@", "!", "/", "_", ";", "[", "]", "(", ")"]

MAPPING = {" loader":"downloader",
           " risk":"riskware",
           "adware":"riskware",
           "backdoor":"trojan",
           "banker":"trojan",
           "bkdr":"trojan",
           "bundler":"riskware",
           "crypt":"ransomware",
           "cryptor":"ransomware",
           "dldr":"downloader",
           "down ":"downloader",
           "downware":"downloader",
           "grayware":"riskware",
           "hack ":"riskware",
           "hackkms":"riskware",
           "hacktool":"riskware",
           "hktl":"riskware",
           "injector":"trojan",
           "keygen":"riskware",
           "kms":"riskware",
           "krypt":"ransomware",
           "kryptik":"ransomware",
           "load ":"downloader",
           "lock":"ransomware",
           "muldown":"downloader",
           "onlinegames":"riskware",
           "ransom ":"ransomware",
           "rkit":"rootkit",
           "rogue":"riskware",
           "rogueware":"riskware",
           "rtk":"rootkit",
           "scareware":"riskware",
           "startpage":"riskware",
           "suspicious":"riskware",
           "sys":"rootkit",
           "trj":"trojan",
           "troj":"trojan",
           "unwanted":"riskware"}

REPLACE = [" tool",
           "agent",
           "application",
           "backdoor",
           "based",
           "behaves",
           "downloader",
           "dropped",
           "dropper",
           "executor",
           "exploit",
           "gen",
           "generic",
           "genome",
           "heur",
           "heuristic",
           "like",
           "malware",
           "obfuscated",
           "optional",
           "packed",
           "posible",
           "possible",
           "program",
           "ransomware",
           "reputation",
           "riskware",
           "rootkit",
           "suspect",
           "trojan",
           "unclassified",
           "unknown",
           "variant",
           "virus",
           "ware",
           "win32 ",
           "win64",
           "worm"]

class VirusTotal(IPlugin, Processing):
    
    def run(self, objfile):
        self.key = "VirusTotal"
        self.score = -1
        self.vtkey = self.options.get("apikey", None)
        self.proxys = self.options.get("proxys", None)
        
        if not self.vtkey:
            raise Exception("VirusTotal API key not configured, skip")
        
        if self.proxys:
            self.proxys = self.proxys.split(';')
        
        # VirusTotal File Report
        returnValue = self.processVirusTotalReport(objfile)
        
        return returnValue
    
    def execVirusTotalRequest(self, objfile):
        response = None
        data = {"resource":objfile.file.get_fileMd5(), "apikey":self.vtkey}
        
        if self.proxys:
            for _ in range(10):
                try:
                    proxy = {"https":random.choice(self.proxys)}
                    response = requests.post(VIRUSTOTAL_URL, data=data, proxies=proxy)
                    
                    if response.status_code != 200: 
                        log.warn("HTTPStatus-Code: %d; Proxy=%s" % (response.status_code,proxy))
                        continue
                except Exception as e:
                    if "ProxyError" in str(e) or "BadStatusLine" in str(e):
                        # remove proxy from list
                        self.proxys.remove(proxy.get("https"))
                        # ignore proxy exception, move to next proxy
                        log.warn("ProxyError: %s" % proxy)
                    else:
                        # no proxy exception
                        log.error("Error: Failed performing request: %s; Proxy=%s" % (e,proxy))
                        raise Exception("Failed performing request: %s; Proxy=%s" % (e,proxy)) 
                else:
                    # success, break loop
                    break
        else:
            try:
                response = requests.post(VIRUSTOTAL_URL, data=data)
            except Exception as e:
                log.error("Error: Failed performing request: %s" % e)
                raise Exception("Failed performing request: %s" % e)
            
        return response

    def processVirusTotalReport(self, objfile):
        result = {}
        malwarenames = []
        
        response = self.execVirusTotalRequest(objfile) 
        if response:
            virustotal = self.response2json(response)
            result['response_code'] = virustotal['response_code']
            
            if virustotal['response_code'] == 1 and 'scans' in virustotal:
                # Extract Malware-Names
                for engine, signature in virustotal.get("scans").items():
                    if signature['detected']:
                        malwarenames.append(signature['result'])
                
                # calculate scoring
                positives = int(virustotal["positives"]) 
                if positives == 0:
                    self.score = 0
                elif positives > 0 and positives < 3:
                    self.score = 25
                elif positives > 3 and positives < 10:
                    self.score = 50     
                elif positives > 10 and positives < 15:
                    self.score = 80
                elif positives >= 15:
                    self.score = 100
    
                # Normalize Step 1
                names = self.normalizeMalwareNamesStep1(malwarenames)
                    
                result["scannerMalwareClassification"] =  {'ransomware':names.count("ransomware"),
                                                           'dropper':names.count("dropper"),
                                                           'exploit':names.count("exploit"),
                                                           'downloader':names.count("downloader"),
                                                           'riskware':names.count("riskware"),
                                                           'rootkit':names.count("rootkit"),
                                                           'worm':names.count("worm"),
                                                           'trojan':names.count("trojan")}
                
                log.debug("scannerMalwareClassification:" + str(result["scannerMalwareClassification"]))
                
                # Normalize Step 2
                names = self.normalizeMalwareNamesStep2(names)
                
                # create Word-Count-Map
                wordCountMap = self.simpleWordFrequency(names)    
                
                result["scannerMalwareFamily"] = self.wordFrequencyReport(wordCountMap)
                log.debug("scannerMalwareFamily:" + str(result["scannerMalwareFamily"]))
                
                result['malwarenames'] = malwarenames 
                result['positives'] = virustotal.get("positives")
                result['total'] = virustotal.get("total")
                result['scan_date'] = virustotal.get("scan_date")
            else: 
                result["verbose_msg"] = "File not found on VirusTotal"  
        else:          
            result["verbose_msg"] = "No response from Virus Total VirusTotal"  
            
        log.debug(result)
        return {"file": result}
    
    def response2json(self, response):
        virustotal = None
        try:
            virustotal = response.json()
            # since python 2.7 the above line causes the Error dict object not callable
        except Exception as e:
            # workaround in case of python 2.7
            if str(e) == "'dict' object is not callable":
                try:
                    virustotal = response.json
                except Exception as e:
                    log.error("Error: Failed parsing the response: {0}".format(e))
                    raise Exception("Failed parsing the response: {0}".format(e))                     
            else:
                log.error("Error: Failed parsing the response: {0}".format(e))
                raise Exception("Failed parsing the response: {0}".format(e)) 
        return virustotal

    def wordFrequencyReport(self, wordCount):
        mostFrequentWord = ''
        countWord = 0
        
        for wort, count in sorted(wordCount.iteritems(), key=lambda (k, v):(v, k)):
            if count > countWord:
                mostFrequentWord = wort
                countWord = count
        
        return {"family":mostFrequentWord, "count":countWord}

    def simpleWordFrequency(self, tmpNames):
        # find the most frequently occuring words
        wordCount = {}
        for wort in tmpNames:
            w = wort.strip()
            if len(w) > 0:
                wordCount[w] = wordCount.get(w, 0) + 1
        
        return wordCount
    
    def normalizeMalwareNamesStep2(self, names):
        # sort Replace Map
        REPLACE.sort(key=lambda item:(-len(item), item))
        # delete not usable words
        for r in REPLACE:
            names = names.replace(r, " ")
        
        # delete special characters
        names = "".join(re.findall("[a-z\s]*", names))
        # delete multiple whitespaces
        names = re.sub('\s{2,}', ' ', names)
        # delete small words
        tmpNames = []
        for name in names.strip().split(' '):
            if len(name.strip()) > 3:
                tmpNames.append(name.strip())
        
        return tmpNames
    
    def normalizeMalwareNamesStep1(self, malwarenames):
        # malwarenames-list to string
        names = " ".join(malwarenames)
        for trn in TRENNER:
            names = names.replace(trn, " ").lower()
        
        for key in sorted(MAPPING, key=len, reverse=True):
            names = names.replace(key, MAPPING[key])
        
        return names