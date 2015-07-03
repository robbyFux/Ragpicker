# Copyright (C) 2013-2015 Ragpicker Developers.
# This file is part of Ragpicker Malware Crawler - http://code.google.com/p/malware-crawler/

import logging
import os
import re
import shutil
import subprocess
import utils.exiftool as exiftool

from core.abstracts import Processing
from core.constants import RAGPICKER_ROOT
from utils.oletools.thirdparty.OleFileIO_PL import OleFileIO_PL
from utils.oletools.olevba import VBA_Parser
from utils.oletools.olevba import detect_autoexec
from utils.oletools.olevba import detect_suspicious
from utils.oletools.olevba import detect_patterns

try:
    from yapsy.IPlugin import IPlugin
except ImportError:
    raise ImportError, 'Yapsy (Yet Another Plugin System) is required to run this program : http://yapsy.sourceforge.net'

log = logging.getLogger("OfficeScan")

CHECK_OUTPUT = ['Malicious Index', 'No malicious traces found', 'RTF file format detected',
                'this file is not a Ms Office OLE2 Compound File',
                'Ms Office OLE2 Compound Format document detected', 'Format type Winword',
                'Format type Excel', 'Format type Powerpoint',
                'VB-MACRO CODE WAS FOUND INSIDE THIS FILE', 'signature found at offset',
                'API-Name', 'PE-File', 'decryption loop detected', 'PEMagic was not 0x010b',
                'OLE File', 'Flash Header']

class OfficeScan(IPlugin, Processing):
    
    def run(self, objfile):
        """ scan for shellcode heuristics, dump object and data areas, as well as PE-Files
        """
        self.key = "OfficeScan"
        self.score = -1
        returnValue = {}
        wine = self.options.get("wine", "/usr/bin/wine")
        brute = self.options.get("brute", True)
        officeMalScanner = os.path.join(RAGPICKER_ROOT, 'utils', 'OfficeMalScanner', 'OfficeMalScanner.exe')
        tmpPath = self.getTmpPath("officeScan_")
        
        try:
            oleFile = os.path.join(tmpPath, "temp.ole")
            # Copy TempFile > new TempDir
            shutil.copyfile(objfile.file.temp_file, oleFile)
            
            # OfficeMalScanner evil.ppt scan brute 
            cmd = wine + " " + officeMalScanner + " '" + oleFile + "' scan"
            if brute:
                cmd = cmd + " brute" 
            log.debug(cmd)
            returnValue["scan"] = self.scanOLE(cmd, tmpPath)
            
            # OfficeMalScanner evil.ppt info
            cmd = wine + " " + officeMalScanner + " '" + oleFile + "' info"
            log.debug(cmd)
            returnValue["info"] = self.scanOLE(cmd, tmpPath)
            
            # Open the OLE file:
            oleFileIO = OleFileIO_PL.OleFileIO(oleFile)

            # Extract metadata
            returnValue["meta"] = self.extractMetadata(oleFileIO)
            # Extract metadata with ExifTool
            returnValue["exifTool"] = self.extractExifToolMeta(oleFile)
            # Show available timestamps
            returnValue["timestamps"] = self.getOleTimes(oleFileIO)
            # check OLE-File is encrypted
            returnValue["isEncrypted"] = self.isEncrypted(oleFileIO)
            
            # https://bitbucket.org/decalage/oletools/wiki/olevba
            # Detect auto-executable macros
            # Detect suspicious VBA keywords often used by malware
            # Extract IOCs/patterns
            returnValue["olevba"] = self.olevba(objfile)
        except (Exception) as e:
            log.error("The module \"OfficeScan\" returned the following error: %s" % e)        
        finally:
            # Delete tmpPath
            shutil.rmtree(tmpPath, ignore_errors=True)        
        
        return returnValue
    
    def olevba(self, objfile):
        analysis = {}
        vba = VBA_Parser(objfile.file.temp_file)
        
        try:
            for (filename, stream_path, vba_filename, vba_code) in vba.extract_macros():
                # Detect auto-executable macros
                autoexec_keywords = detect_autoexec(vba_code)
                if autoexec_keywords:
                    values = []
                    for keyword, description in autoexec_keywords:
                        values.append({"keyword": keyword, "description": description})
                    analysis['AutoExec'] = values
                
                # Detect suspicious VBA keywords
                suspicious_keywords = detect_suspicious(vba_code)
                if suspicious_keywords:
                    values = []
                    for keyword, description in suspicious_keywords:
                        values.append({"keyword": keyword, "description": description})
                    analysis['Suspicious'] = values
                
                # Extract potential IOCs
                patterns = detect_patterns(vba_code)
                if patterns:
                    values = []
                    for pattern_type, value in patterns:
                        values.append({"value": value, "description": pattern_type})
                    analysis['IOC'] = values
        finally:
            vba.close()
            
        return analysis
            
    def isEncrypted(self, oleFileIO):
        if oleFileIO.exists("\x05SummaryInformation"):
            suminfo = oleFileIO.getproperties("\x05SummaryInformation")

            if 0x13 in suminfo:
                # check if bit 1 of security field = 1:
                if suminfo[0x13] & 1:
                    return True
        return False
            
    def getOleTimes(self, oleFileIO):
        times = []
        
        if oleFileIO.root.getmtime() != None and oleFileIO.root.getmtime().year > 1901:
            times.append('Root mtime=%s ctime=%s' % (oleFileIO.root.getmtime(), oleFileIO.root.getctime()))
        
        for obj in oleFileIO.listdir(streams=True, storages=True):
            if oleFileIO.getmtime(obj) != None and oleFileIO.getmtime(obj).year > 1901:
                times.append('%s: mtime=%s ctime=%s' % (repr('/'.join(obj)), oleFileIO.getmtime(obj), oleFileIO.getctime(obj)))       
    
        return times
    
    def extractMetadata(self, oleFileIO):
        metaData = {}
        meta = oleFileIO.get_metadata()
        
        metaData['Codepage'] = meta.codepage
        metaData['Title'] = meta.title
        metaData['Subject'] = meta.subject
        metaData['Author'] = meta.author
        metaData['LastSavedBy'] = meta.last_saved_by
        
        if meta.create_time != None and meta.create_time.year > 1901:
            metaData['CreationDate'] = meta.create_time
        if meta.last_saved_time != None and meta.last_saved_time.year > 1901:
            metaData['LastSavedTime'] = meta.last_saved_time
        
        return metaData
    
    def extractExifToolMeta(self, oleFile):
        metaData = {}
        try:
            with exiftool.ExifTool() as et:
                metadata = et.get_metadata_batch([oleFile])

                if metadata[0].get('File:FileType'):
                    metaData['FileType'] = metadata[0].get('File:FileType') 
                if metadata[0].get('File:MIMEType'):
                    metaData['MIMEType'] = metadata[0].get('File:MIMEType')                                     
                if metadata[0].get('File:FileSize'):
                    metaData['FileSize'] = metadata[0].get('File:FileSize')                 
                if metadata[0].get('File:FileModifyDate'):
                    metaData['FileModifyDate'] = metadata[0].get('File:FileModifyDate')       

                if metadata[0].get('FlashPix:Author'):
                    metaData['Author'] = metadata[0].get('FlashPix:Author')
                if metadata[0].get('FlashPix:LastModifiedBy'):
                    metaData['LastModifiedBy'] = metadata[0].get('FlashPix:LastModifiedBy')
                if metadata[0].get('FlashPix:Company'):
                    metaData['Company'] = metadata[0].get('FlashPix:Company')
                if metadata[0].get('FlashPix:Keywords'):
                    metaData['Keywords'] = metadata[0].get('FlashPix:Keywords')                                     
                if metadata[0].get('FlashPix:CreateDate'):
                    metaData['CreateDate'] = metadata[0].get('FlashPix:CreateDate')                    
                if metadata[0].get('FlashPix:ModifyDate'):
                    metaData['ModifyDate'] = metadata[0].get('FlashPix:ModifyDate')               
                if metadata[0].get('FlashPix:LastModifiedBy'):
                    metaData['LastModifiedBy'] = metadata[0].get('FlashPix:LastModifiedBy')
                if metadata[0].get('FlashPix:LastPrinted'):
                    metaData['LastPrinted'] = metadata[0].get('FlashPix:LastPrinted')
                if metadata[0].get('FlashPix:TotalEditTime'):
                    metaData['TotalEditTime'] = metadata[0].get('FlashPix:TotalEditTime')
                if metadata[0].get('FlashPix:RevisionNumber'):
                    metaData['RevisionNumber'] = metadata[0].get('FlashPix:RevisionNumber')
                if metadata[0].get('FlashPix:CompObjUserType'):
                    metaData['CompObjUserType'] = metadata[0].get('FlashPix:CompObjUserType')
                if metadata[0].get('FlashPix:Software'):
                    metaData['Software'] = metadata[0].get('FlashPix:Software')
                if metadata[0].get('FlashPix:AppVersion'):
                    metaData['AppVersion'] = metadata[0].get('FlashPix:AppVersion')
                if metadata[0].get('FlashPix:CodePage'):
                    metaData['CodePage'] = metadata[0].get('FlashPix:CodePage')
                if metadata[0].get('FlashPix:Template'):
                    metaData['Template'] = metadata[0].get('FlashPix:Template')
                if metadata[0].get('FlashPix:Pages'):
                    metaData['Pages'] = metadata[0].get('FlashPix:Pages')
                if metadata[0].get('FlashPix:Slides'):
                    metaData['Slides'] = metadata[0].get('FlashPix:Slides')
                if metadata[0].get('FlashPix:HiddenSlides'):
                    metaData['HiddenSlides'] = metadata[0].get('FlashPix:HiddenSlides')
                if metadata[0].get('FlashPix:Paragraphs'):
                    metaData['Paragraphs'] = metadata[0].get('FlashPix:Paragraphs')
                if metadata[0].get('FlashPix:Lines'):
                    metaData['Lines'] = metadata[0].get('FlashPix:Lines')
                if metadata[0].get('FlashPix:Words'):
                    metaData['Words'] = metadata[0].get('FlashPix:Words')
                if metadata[0].get('FlashPix:Characters'):
                    metaData['Characters'] = metadata[0].get('FlashPix:Characters')
                if metadata[0].get('FlashPix:CharCountWithSpaces'):
                    metaData['CharCountWithSpaces'] = metadata[0].get('FlashPix:CharCountWithSpaces')
                if metadata[0].get('FlashPix:Notes'):
                    metaData['Notes'] = metadata[0].get('FlashPix:Notes')
                if metadata[0].get('FlashPix:PresentationTarget'):
                    metaData['PresentationTarget'] = metadata[0].get('FlashPix:PresentationTarget')
                if metadata[0].get('FlashPix:MMClips'):
                    metaData['MMClips'] = metadata[0].get('FlashPix:MMClips')
                if metadata[0].get('FlashPix:LinksUpToDate'):
                    metaData['LinksUpToDate'] = metadata[0].get('FlashPix:LinksUpToDate')
                if metadata[0].get('FlashPix:SharedDoc'):
                    metaData['SharedDoc'] = metadata[0].get('FlashPix:SharedDoc')
                if metadata[0].get('FlashPix:Security'):
                    metaData['Security'] = metadata[0].get('FlashPix:Security')
                if metadata[0].get('FlashPix:HyperlinksChanged'):
                    metaData['HyperlinksChanged'] = metadata[0].get('FlashPix:HyperlinksChanged')     

                if metadata[0].get('ExifTool:ExifToolVersion'):
                    metaData['ExifToolVersion'] = metadata[0].get('ExifTool:ExifToolVersion')
                if metadata[0].get('ExifTool:Warning'):
                    metaData['ExifToolWarning'] = metadata[0].get('ExifTool:Warning')               
        except (Exception) as e:
            log.error("exiftool-Error: %s" % e)
        
        return metaData
    
    def scanOLE(self, cmd, tmpPath):
        ret_lst = []
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, cwd=tmpPath, shell=True)
        (stdout, stderr) = process.communicate()
        
        stdout = stdout.decode('utf-8', 'ignore')
        
        if stdout:
            stdout = stdout.replace("\r", "\n")
            stdout = stdout.replace("[*] ", "")
            lines = stdout.split("\n")
            for ln in lines:
                if 'Malicious Index' in ln: 
                    self.score = self.getMaliciousIndex(ln.strip())
                for check in CHECK_OUTPUT:
                    if check in ln: ret_lst.append(ln.strip())
        else: 
            raise Exception(stderr)
        
        if "VB-MACRO CODE WAS FOUND" in str(ret_lst):
            self.score = self.score + 31
        
        log.debug(ret_lst)
        return ret_lst
    
    def getMaliciousIndex(self, data):
        rpd = re.compile('Malicious Index =\s(.+)', re.IGNORECASE)
        rpdFind = re.findall(rpd, data)
        
        for index in rpdFind:
            log.debug("MaliciousIndex = '" + index + "'")
            return int(index)  
        
