# Copyright (C) 2013-2015 Ragpicker Developers.
# This file is part of Ragpicker Malware Crawler - http://code.google.com/p/malware-crawler/

import logging
import time

from core.commonutils import getFileTypeFromBuffer
from core.abstracts import Processing
from utils.pefile import PE
from utils.pefile import PEFormatError
from core.constants import ANTI_DBGS
from core.constants import BLACKLIST_API_FUNCTIONS
from core.constants import GOOD_EP_SECTIONS
from core.constants import VM_SIGN

import utils.pefile as pefile

try:
    from yapsy.IPlugin import IPlugin
except ImportError:
    raise ImportError, 'Yapsy (Yet Another Plugin System) is required to run this program : http://yapsy.sourceforge.net'

log = logging.getLogger("PeFile")

                 
class PeFile(IPlugin, Processing):
    
    def run(self, objfile):
        self.key = "PeFile"
        self.score = 0
        returnValue = {}

        try:
            pe = PE(data=objfile.file.file_data)
                        
            returnValue["PeChecksum"] = self.peChecksum(pe)
            returnValue["PeEntryPoint"] = self.peCheckEP(pe)
            returnValue["PeTlsCallbacks"] = self.checkTlsCallbacks(pe)
            returnValue["PeSections"] = self.peSectionInformations(pe)
            returnValue["Imports"] = self.peImports(pe)
            returnValue["PeRSRC"] = self.peRSRC(pe)
            returnValue["PeTimestamp"] = self.peTimestamp(pe)
            returnValue["PeSuspiciousApiFunctions"] = self.peSuspiciousApiFunctions(pe)
            returnValue["PeCheckAntiDBG"] = self.peCheckAntiDBG(pe)
            returnValue["PeVersionsInfo"] = self.peVersionInfo(pe)
            returnValue["PeCheckAntiVM"] = self.peCheckAntiVM(objfile.file.temp_file)
            # TODO Fehler InvalidDocument bei self.peDebugInformation(pe)
            # returnValue["PeDebugInformation"] = self.peDebugInformation(pe)
        except PEFormatError, e:
            log.warn("Error - No Portable Executable: %s" % e) 
        
        return returnValue
    
    def peVersionInfo(self, pe):
        """Get version info.
        @return: info dict or None.
        """

        infos = []
        if hasattr(pe, "VS_VERSIONINFO"):
            if hasattr(pe, "FileInfo"):
                for entry in pe.FileInfo:
                    try:
                        if hasattr(entry, "StringTable"):
                            for st_entry in entry.StringTable:
                                for str_entry in st_entry.entries.items():
                                    entry = {}
                                    entry["name"] = str_entry[0]
                                    entry["value"] = str_entry[1]
                                    infos.append(entry)
                        elif hasattr(entry, "Var"):
                            for var_entry in entry.Var:
                                if hasattr(var_entry, "entry"):
                                    entry = {}
                                    entry["name"] = var_entry.entry.keys()[0]
                                    entry["value"] = var_entry.entry.values()[0]
                                    infos.append(entry)
                    except:
                        continue

        return infos
    
    def peDebugInformation(self, pe):
        try:
            return pe.DIRECTORY_ENTRY_DEBUG[0].struct
        except:
            try:
                return pe.DIRECTORY_ENTRY_DEBUG.struct
            except:
                try:
                    return pe.DIRECTORY_ENTRY_DEBUG
                except:
                    return None    
    
    def peSuspiciousApiFunctions(self, pe):
        apiFunctions = []
       
        for lib in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in lib.imports:
                    if (imp.name != None) and (imp.name != ""):
                        if imp.name in BLACKLIST_API_FUNCTIONS:
                            apiFunctions.append(imp.name)
                                
        countApiFunctions = len(apiFunctions)
        
        if countApiFunctions > 2 and countApiFunctions < 5:
            self.score += 5
        elif countApiFunctions > 5:
            self.score += 8
        elif countApiFunctions > 10:
            self.score += 10
    
        return sorted(apiFunctions)
    
    def peCheckAntiVM(self, temp_file):
        antiVMTricks = []
        CountTricks = 0
        
        with open(temp_file, "rb") as f:
            buf = f.read()
            for trick in VM_SIGN:
                if buf.find(VM_SIGN[trick][::-1]) > -1:
                    log.debug("Anti VM:\t", trick)
                    antiVMTricks.append(trick)
                    CountTricks = CountTricks + 1
        
        if CountTricks == 0:
            log.debug("Anti VM:\tNone")
            antiVMTricks.append("None")
        else:
            self.score += 10
        
        return antiVMTricks
    
    def peCheckAntiDBG(self, pe):
        returnValue = {}
        antiDbgApi = []
        
        for lib in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in lib.imports:
                    if (imp.name != None) and (imp.name != ""):
                        for antidbg in ANTI_DBGS:
                            if imp.name.startswith(antidbg):
                                antiDbgApi.append(imp.name)
        
        if len(antiDbgApi) > 0:
            self.score = 8
            returnValue = {'Anti_Debug' : 'Yes', 'API_Anti_Debug' : antiDbgApi}
        else:
            returnValue = {'Anti_Debug' : 'No', 'API_Anti_Debug' : ['No suspicious API Anti Debug']}
            
        return returnValue
    
    def peChecksum(self, pe):
        suspicious = False
        claimed = hex(pe.OPTIONAL_HEADER.CheckSum)
        actual = hex(pe.generate_checksum())
        
        if actual != claimed:
            suspicious = True
            self.score += 10
            
        log.info("Claimed: %s, Actual: %s %s" % 
                (claimed, actual, "[SUSPICIOUS]" if suspicious else ""))

        return {'Claimed':claimed,
                'Actual':actual,
                'Suspicious':suspicious}
    
    def checkTlsCallbacks(self, pe):
        tlsAdresses = []
        callbacks = self.getTlsCallbacks(pe)
        
        if len(callbacks):
            self.score += 10
            log.info("TLS callbacks")
            
            for cb in callbacks:
                tlsAdresses.append(hex(cb))
          
        return tlsAdresses
    
    def getTlsCallbacks(self, pe):
        callbacks = []
        if (hasattr(pe, 'DIRECTORY_ENTRY_TLS') and \
                    pe.DIRECTORY_ENTRY_TLS and \
                    pe.DIRECTORY_ENTRY_TLS.struct and \
                    pe.DIRECTORY_ENTRY_TLS.struct.AddressOfCallBacks):
            callback_array_rva = pe.DIRECTORY_ENTRY_TLS.struct.AddressOfCallBacks - pe.OPTIONAL_HEADER.ImageBase 
            idx = 0
            while True:
                func = pe.get_dword_from_data(pe.get_data(callback_array_rva + 4 * idx, 4), 0)
                if func == 0: 
                    break
                callbacks.append(func)
                idx += 1
        return callbacks
    
    def peCheckEP(self, pe):
        suspicious = False
        (ep, name, pos) = self.getEPSection(pe)
        posVsSections = "%d/%d" % (pos, len(pe.sections))
        
        if (name not in GOOD_EP_SECTIONS) or pos == len(pe.sections):
            self.score += 10
            suspicious = True
            
        returnValue = {'EP':hex(ep + pe.OPTIONAL_HEADER.ImageBase),
                       'Name':name,
                       'posVsSections':posVsSections,
                       'Suspicious':suspicious}
            
        return returnValue
        
    def getEPSection(self, pe):
        """ Determine if a PE's entry point is suspicious """
        name = ''
        ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        pos = 0
        for sec in pe.sections:
            if (ep >= sec.VirtualAddress) and \
               (ep < (sec.VirtualAddress + sec.Misc_VirtualSize)):
                name = sec.Name.replace('\x00', '')
                break
            else: 
                pos += 1
        return (ep, name, pos)
    
    def peTimestamp(self, pe):
        peTimeDateStamp = pe.FILE_HEADER.TimeDateStamp
        timeStamp = '0x%-8X' % (peTimeDateStamp)
        try:
            timeStamp += ' [%s UTC]' % time.asctime(time.gmtime(peTimeDateStamp))
            peYear = time.gmtime(peTimeDateStamp)[0]
            thisYear = time.gmtime(time.time())[0]
            if peYear < 2000 or peYear > thisYear:
                timeStamp += " [SUSPICIOUS]"
                self.score += 10
        except:
            timeStamp += ' [SUSPICIOUS]'
            self.score += 10
        
        return timeStamp    
    
    def peSectionInformations(self, pe):
        returnValue = {}
        returnValue["NumberOfSections"] = pe.FILE_HEADER.NumberOfSections
        
        i = 0
        sections = []
        for section in pe.sections:
            i += 1
            info = {}
            sname = section.Name.replace("\x00", "")
            entropy = round(section.get_entropy(), 1)
            info["name"] = sname
            info["md5"] = section.get_hash_md5()                   
            info["virtualAddress"] = hex(section.VirtualAddress)
            info["virtualSize"] = hex(section.Misc_VirtualSize)
            info["sizeOfRawData"] = section.SizeOfRawData
            
            if section.SizeOfRawData == 0 or (entropy > 0 and entropy < 1) or entropy > 6.8:
                self.score += 10
                entropy = str(entropy) + " [SUSPICIOUS]"
               
            info["entropy"] = entropy     
            sections.append(info)
                
        returnValue["Sections"] = sections    
            
        return returnValue
    
    def peImports(self, pe):
        returnValue = []
        
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll = {}
            dllImport = []
            for imp in entry.imports:
                if imp.name: dllImport.append(imp.name)
                
            dll["name"] = entry.dll
            dll["imports"] = sorted(dllImport)
            
            returnValue.append(dll) 
            
        return returnValue
    
    def peRSRC(self, pe):
        returnValue = []
        resources = self.getResources(pe)
        
        if len(resources):
            for rsrc in resources.keys():
                (name, rva, size, type, lang, sublang) = resources[rsrc]
                resource = {}
                resource["name"] = name
                resource["RVA"] = hex(rva)
                resource["Size"] = hex(size)
                resource["Lang"] = lang
                resource["Sublang"] = sublang
                resource["Type"] = type
                returnValue.append(resource)
                  
        return returnValue
    
    def getResources(self, pe):
        ret = {}
        if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
            i = 0
            for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                if resource_type.name is not None:
                    name = "%s" % resource_type.name
                else:
                    name = "%s" % pefile.RESOURCE_TYPE.get(resource_type.struct.Id)
                if name == None:
                    name = "%d" % resource_type.struct.Id
                if hasattr(resource_type, 'directory'):
                    for resource_id in resource_type.directory.entries:
                        if hasattr(resource_id, 'directory'):
                            for resource_lang in resource_id.directory.entries:
                                data = pe.get_data(resource_lang.data.struct.OffsetToData, resource_lang.data.struct.Size)
                                filetype = getFileTypeFromBuffer(data)
                                lang = pefile.LANG.get(resource_lang.data.lang, '*unknown*')
                                sublang = pefile.get_sublang_name_for_lang(resource_lang.data.lang, resource_lang.data.sublang)
                                ret[i] = (name, resource_lang.data.struct.OffsetToData, resource_lang.data.struct.Size, filetype, lang, sublang)
                                i += 1
        return ret
