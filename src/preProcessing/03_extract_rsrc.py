# Copyright (C) 2013-2015 Ragpicker Developers.
# This file is part of Ragpicker Malware Crawler - http://code.google.com/p/malware-crawler/

import logging

from core.commonutils import getFileTypeFromBuffer
from core.abstracts import Processing
from utils.pefile import PE
from utils.pefile import PEFormatError

try:
    from yapsy.IPlugin import IPlugin
except ImportError:
    raise ImportError, 'Yapsy (Yet Another Plugin System) is required to run this program : http://yapsy.sourceforge.net'

log = logging.getLogger("ExtractRSRC")

class ExtractRSRC(IPlugin, Processing):

    def run(self, objfile):
        self.extractTypes = self.options.get("extracttypes")
        
        try:
            pe = PE(data=objfile.file.file_data)
            resources = self.getResources(pe)
            
            if objfile.unpacked_file:
                pe = PE(data=objfile.unpacked_file.file_data)
                resources = resources + self.getResources(pe)
            
            for resource in resources:
                objfile.add_included_file(resource)   
        except PEFormatError, e:
            log.warn("Error - No Portable Executable: %s" % e) 
        except (Exception) as e:
            log.error("The module \"ExtractRSRC\" returned the following error: %s" % e)        
        finally:
            pass
            
        return objfile

    def getResources(self, pe):
        ret = []
        if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
            for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                if hasattr(resource_type, 'directory'):
                    for resource_id in resource_type.directory.entries:
                        if hasattr(resource_id, 'directory'):
                            for resource_lang in resource_id.directory.entries:
                                data = pe.get_data(resource_lang.data.struct.OffsetToData, resource_lang.data.struct.Size)
                                filetype = getFileTypeFromBuffer(data)
                                
                                log.debug("Found: " + filetype)
                                
                                if filetype in self.extractTypes:
                                    #TODO: RAR und ZIP entpacken!!!
                                    ret.append(data)
                                    log.info("Append File: " + filetype)
        return ret
