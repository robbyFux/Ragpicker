# Copyright (C) 2013-2015 Ragpicker Developers.
# This file is part of Ragpicker Malware Crawler - http://code.google.com/p/malware-crawler/

import bz2
import logging
import string
import hashlib
import utils.pefile as pefile

from core.abstracts import Processing
from core.constants import RAGPICKER_VERSION
from utils.pefile import PE
from utils.pefile import PEFormatError
from utils.peutils import is_probably_packed

try:
    import bitstring
except ImportError:
    raise ImportError, 'bitstring is required to run this program :  https://code.google.com/p/python-bitstring/'

try:
    from yapsy.IPlugin import IPlugin
except ImportError:
    raise ImportError, 'Yapsy (Yet Another Plugin System) is required to run this program : http://yapsy.sourceforge.net'

log = logging.getLogger("ProcessingInfo")

class info(IPlugin, Processing):
    
    def run(self, objfile):
        self.key = "Info"
        self.score = -1
        isProbablyPacked = False
        returnValue = {}
        
        infos = {}
        infos["uuid"] = objfile.get_uuid()
        infos["ragpicker_version"] = RAGPICKER_VERSION
        infos["started"] = self.task["started_on"]                       
        returnValue["analyse"] = infos 
        
        infos = {}
        infos["extension"] = objfile.file.file_extension()    
        
        if objfile.file.get_type() == 'PE32' or objfile.file.get_type() == 'PE32+' or objfile.file.get_type() == 'MS-DOS':
            try:
                pe = PE(data=objfile.file.file_data)
                
                isProbablyPacked = is_probably_packed(pe)
                
                if pe.PE_TYPE == pefile.OPTIONAL_HEADER_MAGIC_PE:
                    infos["Architecture"] = "32-Bit"
                elif pe.PE_TYPE == pefile.OPTIONAL_HEADER_MAGIC_PE_PLUS:
                    infos["Architecture"] = "64-Bit"                
                
                infos["CPU"] = self.getMaschineType(pe) 
                infos["Subsystem"] = self.getSubsystem(pe) 
                infos["DLL"] = pe.is_dll()
                infos["EXE"] = pe.is_exe()
                infos["DRIVER"] = pe.is_driver()
                infos["isProbablyPacked"] = isProbablyPacked
                
                # imphash -> Tracking Malware with Import Hashing (https://www.mandiant.com/blog/tracking-malware-import-hashing)
                infos["imphash"] = pe.get_imphash()
                # https://www.usenix.org/legacy/event/leet09/tech/full_papers/wicherski/wicherski.pdf
                infos["pehash"] = self.getPeHash(pe)
                                
                if self.getDigitalSignature(pe):
                    infos["digitalSignature"] = "SignedFile"
                else:
                    infos["digitalSignature"] = "UnsignedFile"
                    
                if isProbablyPacked:
                    self.score = 10
            except PEFormatError, e:
                log.warn("Error - No Portable Executable: %s" % e)         
        
        infos["filename"] = objfile.get_url_filename()
        infos["size"] = objfile.file.get_size()
        infos["type"] = objfile.file.get_type()
        infos["md5"] = objfile.file.get_fileMd5()
        infos["sha1"] = objfile.file.get_fileSha1()
        infos["sha256"] = objfile.file.get_fileSha256()  
        
        #Family
        family = {}
        if objfile.family.unpackedObjectSHA256 != "":
            family["unpackedObjectSHA256"] = objfile.family.unpackedObjectSHA256
        if len(objfile.family.siblingObjectsSHA256) > 0:
            family["siblingObjectsSHA256"] = objfile.family.siblingObjectsSHA256
        
        infos["family"] = family  
                
        returnValue["file"] = infos 
        
        infos = {}
        infos["url"] = objfile.url   
        infos["md5"] = objfile.get_urlMd5()
        infos["hostname"] = objfile.get_url_hostname()
        infos["protocol"] = objfile.get_url_protocol()
        infos["port"] = objfile.get_url_port() 
        returnValue["url"] = infos 
            
        return returnValue
    
    def getPeHash(self, exe):
        try:
            #image characteristics
            img_chars = bitstring.BitArray(hex(exe.FILE_HEADER.Characteristics))
            #pad to 16 bits
            img_chars = bitstring.BitArray(bytes=img_chars.tobytes())
            img_chars_xor = img_chars[0:7] ^ img_chars[8:15]
         
            #start to build pehash
            pehash_bin = bitstring.BitArray(img_chars_xor)
         
            #subsystem -
            sub_chars = bitstring.BitArray(hex(exe.FILE_HEADER.Machine))
            #pad to 16 bits
            sub_chars = bitstring.BitArray(bytes=sub_chars.tobytes())
            sub_chars_xor = sub_chars[0:7] ^ sub_chars[8:15]
            pehash_bin.append(sub_chars_xor)
         
            #Stack Commit Size
            stk_size = bitstring.BitArray(hex(exe.OPTIONAL_HEADER.SizeOfStackCommit))
            stk_size_bits = string.zfill(stk_size.bin, 32)
            #now xor the bits
            stk_size = bitstring.BitArray(bin=stk_size_bits)
            stk_size_xor = stk_size[8:15] ^ stk_size[16:23] ^ stk_size[24:31]
            #pad to 8 bits
            stk_size_xor = bitstring.BitArray(bytes=stk_size_xor.tobytes())
            pehash_bin.append(stk_size_xor)
         
            #Heap Commit Size
            hp_size = bitstring.BitArray(hex(exe.OPTIONAL_HEADER.SizeOfHeapCommit))
            hp_size_bits = string.zfill(hp_size.bin, 32)
            #now xor the bits
            hp_size = bitstring.BitArray(bin=hp_size_bits)
            hp_size_xor = hp_size[8:15] ^ hp_size[16:23] ^ hp_size[24:31]
            #pad to 8 bits
            hp_size_xor = bitstring.BitArray(bytes=hp_size_xor.tobytes())
            pehash_bin.append(hp_size_xor)
         
            #Section chars
            for section in exe.sections:
                #virutal address
                sect_va =  bitstring.BitArray(hex(section.VirtualAddress))
                sect_va = bitstring.BitArray(bytes=sect_va.tobytes())
                pehash_bin.append(sect_va)    
         
                #rawsize
                sect_rs =  bitstring.BitArray(hex(section.SizeOfRawData))
                sect_rs = bitstring.BitArray(bytes=sect_rs.tobytes())
                sect_rs_bits = string.zfill(sect_rs.bin, 32)
                sect_rs = bitstring.BitArray(bin=sect_rs_bits)
                sect_rs = bitstring.BitArray(bytes=sect_rs.tobytes())
                sect_rs_bits = sect_rs[8:31]
                pehash_bin.append(sect_rs_bits)
         
                #section chars
                sect_chars =  bitstring.BitArray(hex(section.Characteristics))
                sect_chars = bitstring.BitArray(bytes=sect_chars.tobytes())
                sect_chars_xor = sect_chars[16:23] ^ sect_chars[24:31]
                pehash_bin.append(sect_chars_xor)
         
                #entropy calulation
                address = section.VirtualAddress
                size = section.SizeOfRawData
                raw = exe.write()[address+size:]
                if size == 0:
                    kolmog = bitstring.BitArray(float=1, length=32)
                    pehash_bin.append(kolmog[0:7])
                    continue
                bz2_raw = bz2.compress(raw)
                bz2_size = len(bz2_raw)
                #k = round(bz2_size / size, 5)
                k = bz2_size / size
                kolmog = bitstring.BitArray(float=k, length=32)
                pehash_bin.append(kolmog[0:7])
         
            m = hashlib.sha1()
            m.update(pehash_bin.tobytes())
            return m.hexdigest()
        except Exception, e:
            log.error("Error calculate PeHash: %s" % e)

    def getDigitalSignature(self, pe):
        """Extracts the digital signature from file
           Returns the signature
        """
        
        address = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']].VirtualAddress
        size = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']].Size
    
        if address == 0:
            log.info('source file not signed')
            return None
        
        signature = pe.write()[address + 8:]
        
        return signature

    def getSubsystem(self, pe):
        subsystem = pefile.SUBSYSTEM_TYPE[pe.OPTIONAL_HEADER.Subsystem] 
        subsystem = subsystem.replace('IMAGE_SUBSYSTEM_', '')
        subsystem = subsystem.replace('_', '-')
        return subsystem

    def getMaschineType(self, pe):
        maschine = pefile.MACHINE_TYPE[pe.FILE_HEADER.Machine]
        maschine = maschine.replace('IMAGE_FILE_MACHINE_', '')
        maschine = maschine.replace('_', '-')
        return maschine


