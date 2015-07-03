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


try:
    from yapsy.IPlugin import IPlugin
except ImportError:
    raise ImportError, 'Yapsy (Yet Another Plugin System) is required to run this program : http://yapsy.sourceforge.net'

log = logging.getLogger("RTFScan")

CHECK_OUTPUT = ['This file contains overlay data', 'OLE_DOCUMENT has been found', 'Embedded OLE document found', 'other PE-file indications were found', 'decryption loop detected at offset', 'API-Name', 'No malicious traces found', 'Malicious Index', 'This file is not a RTF-file', 'signature found at offset'] 

class RTFScan(IPlugin, Processing):
    
    def run(self, objfile):
        """ scan for shellcode heuristics, dump object and data areas, as well as PE-Files
        """
        self.key = "RTFScan"
        self.score = -1
        returnValue = {}
        wine = self.options.get("wine", "/usr/bin/wine")
        rtfScan = os.path.join(RAGPICKER_ROOT, 'utils', 'OfficeMalScanner', 'RTFScan.exe')
        tmpPath = self.getTmpPath("rtfScan_")
        
        try:
            rtfFile = os.path.join(tmpPath, "temp.rtf")
            # Copy TempFile > new TempDir
            shutil.copyfile(objfile.file.temp_file, rtfFile)
            cmd = wine + " " + rtfScan + " '" + rtfFile + "' scan"
            log.debug(cmd)
            
            returnValue["scan"] = self.ScanRTF(cmd, tmpPath)
            
            # Extract metadata
            returnValue["meta"] = self.extractMetadata(rtfFile)

        except (Exception) as e:
            log.error("The module \"RTFScan\" returned the following error: %s" % e)        
        finally:
            # Delete tmpPath
            shutil.rmtree(tmpPath, ignore_errors=True)        
        
        return returnValue
    
    def ScanRTF(self, cmd, tmpPath):
        ret_lst = []
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, cwd=tmpPath, shell=True)
        (stdout, stderr) = process.communicate()
        
        stdout = stdout.decode('utf-8', 'ignore')
        stdout = stdout.replace("+++++ ", "")
        stdout = stdout.replace(" +++++", "")
        stdout = stdout.replace("!!! ", "")
        stdout = stdout.replace(" !!!", "")
        
        if stdout:
            lines = stdout.split("\n")
            for ln in lines:
                if 'Malicious Index' in ln: 
                    self.score = self.getMaliciousIndex(ln.strip())
                for check in CHECK_OUTPUT:
                    if check in ln: ret_lst.append(ln.strip())
        else: 
            raise Exception(stderr) 
        
        log.debug(ret_lst)
        return ret_lst
    
    def extractMetadata(self, rtfFile):
        metaData = {}
        try:
            with exiftool.ExifTool() as et:
                metadata = et.get_metadata_batch([rtfFile])

                if metadata[0].get('File:FileType'):
                    metaData['FileType'] = metadata[0].get('File:FileType') 
                if metadata[0].get('File:MIMEType'):
                    metaData['MIMEType'] = metadata[0].get('File:MIMEType')                                     
                if metadata[0].get('File:FileSize'):
                    metaData['FileSize'] = metadata[0].get('File:FileSize')                 
                if metadata[0].get('File:FileModifyDate'):
                    metaData['FileModifyDate'] = metadata[0].get('File:FileModifyDate')       
    
                if metadata[0].get('RTF:Title'):
                    metaData['Title'] = metadata[0].get('RTF:Title')
                if metadata[0].get('RTF:Author'):
                    metaData['Author'] = metadata[0].get('RTF:Author')
                if metadata[0].get('RTF:LastModifiedBy'):
                    metaData['LastModifiedBy'] = metadata[0].get('RTF:LastModifiedBy')
                if metadata[0].get('RTF:Comments'):
                    metaData['Comments'] = metadata[0].get('RTF:Comments')   
                    
                if metadata[0].get('RTF:Pages'):
                    metaData['Pages'] = metadata[0].get('RTF:Pages')
                if metadata[0].get('RTF:Characters'):
                    metaData['Characters'] = metadata[0].get('RTF:Characters')
                if metadata[0].get('RTF:CharactersWithSpaces'):
                    metaData['CharactersWithSpaces'] = metadata[0].get('RTF:CharactersWithSpaces')                       
                if metadata[0].get('RTF:Words'):
                    metaData['Words'] = metadata[0].get('RTF:Words')
                                
                if metadata[0].get('RTF:Password'):
                    metaData['RTFPassword'] = metadata[0].get('RTF:Password')
                if metadata[0].get('RTF:InternalVersionNumber'):
                    metaData['InternalVersionNumber'] = metadata[0].get('RTF:InternalVersionNumber')
                if metadata[0].get('RTF:RevisionNumber'):
                    metaData['RevisionNumber'] = metadata[0].get('RTF:RevisionNumber')
                if metadata[0].get('RTF:TotalEditTime'):
                    metaData['TotalEditTime'] = metadata[0].get('RTF:TotalEditTime')
  
                if metadata[0].get('RTF:CreateDate'):
                    metaData['RTFCreateDate'] = metadata[0].get('RTF:CreateDate')                 
                if metadata[0].get('RTF:ModifyDate'):
                    metaData['RTFModifyDate'] = metadata[0].get('RTF:ModifyDate')              

                if metadata[0].get('ExifTool:ExifToolVersion'):
                    metaData['ExifToolVersion'] = metadata[0].get('ExifTool:ExifToolVersion')
                if metadata[0].get('ExifTool:Warning'):
                    metaData['ExifToolWarning'] = metadata[0].get('ExifTool:Warning')               
        except (Exception) as e:
            log.error("exiftool-Error: %s" % e)
        
        return metaData
    
    def getMaliciousIndex(self, data):
        rpd = re.compile('Malicious Index =\s(.+)', re.IGNORECASE)
        rpdFind = re.findall(rpd, data)
        
        for index in rpdFind:
            log.debug("MaliciousIndex = '" + index + "'")
            return int(index)  
        
