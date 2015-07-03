#!/usr/bin/env python
# -*- coding: utf-8 -*-

#  ██╗   ██╗████████╗████████╗ ██████╗  ██████╗ ██╗     
#  ██║   ██║╚══██╔══╝╚══██╔══╝██╔═══██╗██╔═══██╗██║     
#  ██║   ██║   ██║█████╗██║   ██║   ██║██║   ██║██║     
#  ╚██╗ ██╔╝   ██║╚════╝██║   ██║   ██║██║   ██║██║     
#   ╚████╔╝    ██║      ██║   ╚██████╔╝╚██████╔╝███████╗
#    ╚═══╝     ╚═╝      ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝ v0.9.3
#
# Find the name of the evil
#
# vtTool offers a convenient way of determining the likely name of malware 
# by querying VirusTotal using the file’s hash via the command line. 
#
# Robby Zeitfuchs - robby@zeitfuchs.org - 2013-2015
# Mark Lawrenz - Mark.Lawrenz@web.de
#
# any subjection, tips, improvement are welcome
#
# Install on Ubuntu:
# sudo apt-get -y install python-numpy python-scipy python-levenshtein
# sudo pip install requests fuzzywuzzy scikit-learn
# wget https://malware-crawler.googlecode.com/svn/MalwareCrawler/src/tools/vtTool.py
# chmod a+xr vtTool.py
# sudo mv vtTool.py /usr/local/bin
#
# Licence: GNU GPL v.3.0
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.                                                     

import re
import sys
import time
import argparse
import logging
logging.captureWarnings(True)

DEBUG = False
CLUSTER = True

try:
    import requests
    import numpy as np
    from fuzzywuzzy import fuzz
    from sklearn.cluster import DBSCAN
except ImportError:
    CLUSTER = False

VIRUSTOTAL_URL = 'https://www.virustotal.com/vtapi/v2/file/report'
VIRUSTOTAL_URL_SUBMIT = 'https://www.virustotal.com/vtapi/v2/file/scan'
KEY = 'a0283a2c3d55728300d064874239b5346fb991317e8449fe43c902879d758088'

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
           "download":"downloader",
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

def install():
    print "\n"
    print "Lexical clustering requires the following dependencies:"
    print "numpy: http://scikit-learn.org/stable/install.html"
    print "scikit-learn: http://scikit-learn.org/stable/install.html"
    print "FuzzyWuzzy: https://github.com/seatgeek/fuzzywuzzy"
    print "python-levenshtein: https://github.com/miohtama/python-Levenshtein"
    print "requests: http://docs.python-requests.org/en/latest/"
    print "\n"
    print "Install on Ubuntu:"
    print " sudo apt-get -y install python-numpy python-scipy python-levenshtein"
    print " sudo pip install requests fuzzywuzzy scikit-learn"
    print "\n"

def logo():
    print "\n"
    print "  ██╗   ██╗████████╗████████╗ ██████╗  ██████╗ ██╗"
    print "  ██║   ██║╚══██╔══╝╚══██╔══╝██╔═══██╗██╔═══██╗██║"
    print "  ██║   ██║   ██║█████╗██║   ██║   ██║██║   ██║██║"
    print "  ╚██╗ ██╔╝   ██║╚════╝██║   ██║   ██║██║   ██║██║"
    print "   ╚████╔╝    ██║      ██║   ╚██████╔╝╚██████╔╝███████╗"
    print "    ╚═══╝     ╚═╝      ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝ v0.9.4"
    print " Find the name of the evil"
    print " Robby Zeitfuchs, Mark Lawrenz"
    print " Copyright (c) 2013-2015\n"

def response2json(response):
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
                print "Error: Failed parsing the response: {0}".format(e)
                raise Exception("Failed parsing the response: {0}".format(e))                     
        else:
            print "Error: Failed parsing the response: {0}".format(e)
            raise Exception("Failed parsing the response: {0}".format(e)) 
    return virustotal

# Static variable decorator for function
def staticVar(varname, value):
    def decorate(func):
        setattr(func, varname, value)
        return func
    return decorate

@staticVar("counter", 0)
@staticVar("startTime", 0)
def processHash(malware_hash):
    malwarenames = []
    positives = 0
    total = 0
    data = {'resource' : malware_hash, 'apikey' : KEY}

    # Set on first request
    if processHash.startTime == 0:
        processHash.startTime = time.time()

    # Increment every request
    processHash.counter += 1

    try:
        response = requests.post(VIRUSTOTAL_URL, data=data)
        virustotal = response2json(response)
    except Exception as e:
        print "Error: Failed performing request: %s"% e
        return
    
    # Determine minimum time we need to wait for limit to reset
    waitTime = 59 - int(time.time() - processHash.startTime)
    #print "start_time=%s, wait_time=%d, counter=%d" % (str(processHash.start_time), wait_time,processHash.counter)

    if processHash.counter == 4 and waitTime > 0:
        waitTime = 60
        print "Warn: Limit requests per minute reached (%d per minute); waiting %d seconds" % (processHash.counter, waitTime)
        time.sleep(waitTime)

        # Reset static vars
        processHash.counter = 0
        processHash.startTime = 0
    
    if 'scans' in virustotal:
        for engine, signature in virustotal.get("scans").items():
            if signature['detected']:
                malwarenames.append(signature['result'])
                
        positives = virustotal.get("positives")
        total = virustotal.get("total")
        
        return {"malwarenames":malwarenames, "positives":positives, "total":total}
    return None

def wordFrequencyReport(wordCount):
    mostFrequentWord = ''
    countWord = 0
    secWord = ''
    secCountWord = 0
    for wort, count in sorted(wordCount.iteritems(), key=lambda (k, v):(v, k)):
        if DEBUG:
            print "'%s':%s," % (wort, count)
        if count > countWord:
            secWord = mostFrequentWord
            secCountWord = countWord
            mostFrequentWord = wort
            countWord = count
    
    print '\n--- scanner malware family determination ---'
    print "Most frequent word: %s (count=%d)" % (mostFrequentWord, countWord)
    if secCountWord > 0:
        print "Second most frequent word: %s (count=%d)" % (secWord, secCountWord)
    print "\n"

def simpleWordFrequency(tmpNames):
    # find the most frequently occuring words
    wordCount = {}
    for wort in tmpNames:
        w = wort.strip()
        if len(w) > 0:
            wordCount[w] = wordCount.get(w, 0) + 1
    
    return wordCount

def normalizeMalwareNamesStep2(names):
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

def normalizeMalwareNamesStep1(malwarenames):
    # malwarenames-list to string
    names = " ".join(malwarenames)
    for trn in TRENNER:
        names = names.replace(trn, " ").lower()
    
    for key in sorted(MAPPING, key=len, reverse=True):
        names = names.replace(key, MAPPING[key])
    
    return names

# similarity from the ratio, token_sort and token_set ratio methods in FuzzyWuzzy
def computeSimilarity(s1, s2):
    return 1.0 - (0.01 * max(
        fuzz.ratio(s1, s2),
        fuzz.token_sort_ratio(s1, s2),
        fuzz.token_set_ratio(s1, s2)))
    
def uniqueList(l):
    ulist = []
    [ulist.append(x) for x in l if x not in ulist]
    return ulist

def clusterMalwareNames(malwareNames):
    # strictly lexical clustering over malware-names
    wordCount = {}
    # create a distance matrix
    matrix = np.zeros((len(malwareNames), len(malwareNames)))
    for i in range(len(malwareNames)):
        for j in range(len(malwareNames)):
            if matrix[i, j] == 0.0:        
                matrix[i, j] = computeSimilarity(malwareNames[i], malwareNames[j])
                matrix[j, i] = matrix[i, j]
    
    # Scikit-Learn's DBSCAN implementation to cluster the malware-names
    clust = DBSCAN(eps=0.1, min_samples=5, metric="precomputed")
    clust.fit(matrix)    
    
    preds = clust.labels_
    clabels = np.unique(preds)
    
    # create Word-Count Map
    for i in range(clabels.shape[0]):
        if clabels[i] < 0:
            continue
        
        cmem_ids = np.where(preds == clabels[i])[0]
        cmembers = []
        
        for cmem_id in cmem_ids:
            cmembers.append(malwareNames[cmem_id])
        
        wordCount[", ".join(uniqueList(cmembers))] = len(cmem_ids)
    return wordCount

def main(malware_hashes):
    malware_hashes = malware_hashes.split(",")
    malwarenames = []
    total = 0
    positives = 0
    
    if len(malware_hashes) > 4:
        print "Warn: Virustotal 4 requests/minute limitation!"
    
    for malware_hash in malware_hashes:
        malware_hash = malware_hash.strip()
        if not ((len(malware_hash) == 64) or (len(malware_hash) == 32) or (len(malware_hash) == 40)):
            print "Error: This is not a valid hash!: " + malware_hash + ". Please submit a valid SHA256, SHA1, or MD5 hash."
            continue
        
        values = processHash(malware_hash)
        if values:
            malwarenames += values.get("malwarenames")
            total += values.get("total")
            positives += values.get("positives")
    
    # Normalize Step 1
    names = normalizeMalwareNamesStep1(malwarenames)
    
    print '\n--- scanner malware classification ---'
    print '  ransomware: ' + str(names.count("ransomware"))
    print '     dropper: ' + str(names.count("dropper"))
    print '     exploit: ' + str(names.count("exploit"))
    print '  downloader: ' + str(names.count("downloader"))
    print '    riskware: ' + str(names.count("riskware"))
    print '     rootkit: ' + str(names.count("rootkit"))
    print '        worm: ' + str(names.count("worm"))
    print '      trojan: ' + str(names.count("trojan"))
    print "\n"
    
    print '--- average detection rate ---'
    print 'count hashes: %d' % len(malware_hashes)
    print 'totalscanner: %d' % (total/len(malware_hashes))
    print '   positives: %d' % (positives/len(malware_hashes))
    print "\n"
    
    # Normalize Step 2
    names = normalizeMalwareNamesStep2(names)
    
    if DEBUG:
        print " ".join(names)
    
    # create Word-Count-Map
    if CLUSTER:
        # strictly lexical clustering over malware-names
        wordCountMap = clusterMalwareNames(names)
    else:
        wordCountMap = simpleWordFrequency(names)
    
    # Print the Result
    wordFrequencyReport(wordCountMap)
    
if __name__ == '__main__':         
    parser = argparse.ArgumentParser(description='VirusTotal MalwareName-Tool')
    parser.add_argument("-hash", "--hashlist", help="Malware hash or CSV Hashlist", required=True)
    parser.add_argument("--debug", help="Debugmodus", action="store_true", default=False)
    parser.add_argument("--cluster", help="Strictly lexical clustering over malware-names", action="store_true", default=False)
    args = parser.parse_args()
    
    DEBUG = args.debug
    
    # Print Logo 
    logo()
    
    if not args.cluster:
        CLUSTER = False
    elif args.cluster and not CLUSTER:
        install()
        sys.exit()
    
    main(args.hashlist)