# Copyright (C) 2013-2015 Ragpicker Developers.
# This file is part of Ragpicker Malware Crawler - http://code.google.com/p/malware-crawler/

import logging

from core.abstracts import Processing
from utils.pdfid import PDFiD


try:
    from yapsy.IPlugin import IPlugin
except ImportError:
    raise ImportError, 'Yapsy (Yet Another Plugin System) is required to run this program : http://yapsy.sourceforge.net'

log = logging.getLogger("ProcessingPDFID")

RISKY_PDF_SECTIONS = ['/OpenAction', '/AA', '/JS', '/JavaScript', '/Launch', '/URI', '/Action', '/GoToR', '/RichMedia', '/ObjStm']

class PDFID(IPlugin, Processing):
    
    def run(self, objfile):
        """Gets PDF identify and informations.
        """
        self.key = "PDFID"
        self.score = -1
        returnValue = None
        
        try:
            pdfIdXML = PDFiD(file=objfile.file.temp_file, allNames=False, extraData=True, disarm=False, force=True)
            returnValue = self.xml2dic(pdfIdXML)
            log.debug("PDFID returns: %s" % returnValue)
        except Exception, e:
            log.warn("Error - PDFID returns: %s" % e)        
        
        return returnValue
    
    def xml2dic(self, xmlDoc):
        scoreHit = 0
        # Get Top Layer Data
        errorOccured = xmlDoc.documentElement.getAttribute('ErrorOccured')
        errorMessage = xmlDoc.documentElement.getAttribute('ErrorMessage')
        header = xmlDoc.documentElement.getAttribute('Header')
        isPdf = xmlDoc.documentElement.getAttribute('IsPDF')
    
        # extra data
        countEof = xmlDoc.documentElement.getAttribute('CountEOF')
        countChatAfterLastEof = xmlDoc.documentElement.getAttribute('CountCharsAfterLastEOF')
        totalEntropy = xmlDoc.documentElement.getAttribute('TotalEntropy')
        streamEntropy = xmlDoc.documentElement.getAttribute('StreamEntropy')
        nonStreamEntropy = xmlDoc.documentElement.getAttribute('NonStreamEntropy')
        
        keywords = []
    
        # grab all keywords
        for node in xmlDoc.documentElement.getElementsByTagName('Keywords')[0].childNodes:
            name = node.getAttribute('Name')
            count = int(node.getAttribute('Count'))
            if int(node.getAttribute('HexcodeCount')) > 0:
                hexCount = int(node.getAttribute('HexcodeCount'))
            else:
                hexCount = 0
            
            if name in RISKY_PDF_SECTIONS and count > 0:
                name = "[RISKY] %s" % name
                scoreHit += 1
            
            if name == "/Page" and count < 2:
                scoreHit += 1
            
            keyword = { 'count':count, 'hexcodecount':hexCount, 'name':name }
            keywords.append(keyword)
            
        if totalEntropy > 5.9:
            scoreHit += 1
    
        data = {'header':header,
                'isPdf':isPdf,
                'errorOccured':errorOccured,
                'errorMessage':errorMessage,
                'totalEntropy':totalEntropy,
                'streamEntropy':streamEntropy,
                'countEof':countEof,
                'countChatAfterLastEof':countChatAfterLastEof,
                'nonStreamEntropy':nonStreamEntropy,
                'keywords':keywords }
        
        # Calculate Scoring
        if scoreHit == 2:
            self.score = 8
        elif scoreHit > 2:
            self.score = 10
        
        return data
