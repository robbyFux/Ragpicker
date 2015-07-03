# Copyright (C) 2013-2015 Ragpicker Developers.
# This file is part of Ragpicker Malware Crawler - http://code.google.com/p/malware-crawler/

import logging
import os
import tempfile

from core.abstracts import Report


try:
    from yapsy.IPlugin import IPlugin
except ImportError:
    raise ImportError, 'Yapsy (Yet Another Plugin System) is required to run this program : http://yapsy.sourceforge.net'

log = logging.getLogger(__name__)

class FileDump(IPlugin, Report):
    """Save downloaded file on the file system"""

    def run(self, results, objfile):
        dumpdir = self.options.get("dumpdir", None)
        suffix = self.options.get("suffix", None)

        if not dumpdir:
            raise Exception("dumpdir not configured, skip")
         
        try:
            if not os.path.exists(dumpdir):
                os.makedirs(dumpdir)  
            d = tempfile.mkdtemp(dir=dumpdir)
        except Exception as e:
            raise Exception('Could not open %s for writing (%s)', dumpdir, e)
        else:
            os.rmdir(d)
        
        dest = dumpdir + objfile.file.get_type()
  
        if not os.path.exists(dest):
            os.makedirs(dest)
        
        # Save file
        fpath = dest + '/' + objfile.file.get_fileMd5() + self.getFileExtension(suffix, objfile.file)
        self.saveFile(objfile.file.file_data, fpath)
        
        # Save unpacked file
        if objfile.unpacked_file:
            fpath = "%s/%s_unpacked_(%s)%s" % (dest, objfile.unpacked_file.get_fileMd5(), objfile.file.get_fileMd5(), \
                                               self.getFileExtension(suffix, objfile.unpacked_file))
            self.saveFile(objfile.unpacked_file.file_data, fpath)    
            
        # Save included files
        if len(objfile.included_files) > 0:
            log.info("Save included files")
            for incl_file in objfile.included_files:
                log.info("File: " + incl_file.get_fileMd5())
                fpath = "%s/%s_included_(%s)%s" % (dest, incl_file.get_fileMd5(), objfile.file.get_fileMd5(), \
                                                   self.getFileExtension(suffix, incl_file))
                self.saveFile(incl_file.file_data, fpath)    
            
        return None
    
    def getFileExtension(self, suffix, file):
        if file.file_extension():
            file_extension = '.' + file.file_extension() + suffix
        else:
            file_extension = suffix
        return file_extension    
    
    def saveFile(self, file_data, fpath):
        if not os.path.exists(fpath):
            file = open(fpath, 'wb')
            file.write(file_data)
            file.close
            log.info("Saved file %s" % fpath)
