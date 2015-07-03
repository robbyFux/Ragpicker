# Copyright (C) 2013-2015 Ragpicker Developers.
# This file is part of Ragpicker Malware Crawler - http://code.google.com/p/malware-crawler/

from os import walk
from os.path import join
import logging
import shutil
import tempfile

from core.abstracts import Processing
import core.commonutils as commonutils


try:
    from yapsy.IPlugin import IPlugin
except ImportError:
    raise ImportError, 'Yapsy (Yet Another Plugin System) is required to run this program : http://yapsy.sourceforge.net'

log = logging.getLogger("UnpackArchive")

class UnpackArchive(IPlugin, Processing):

    def run(self, objfile):
        tmpdir = tempfile.mkdtemp()
        tmp_files = []
        
        try:
            commonutils.unpackArchive(objfile.file.temp_file, tmpdir)
                
            for root, dirs, files in walk(tmpdir):
                for file in files:
                    full_path = join(root, file)
                    if not commonutils.isArchive(full_path):
                        tmp_files.append(full_path)
            
            if len(tmp_files) == 1 and commonutils.isPermittedType(tmp_files[0]):
                # len == 1 > easy, replace archive file in objfile
                objfile.set_file_from_path(tmp_files[0])
            else:
                for file in tmp_files: 
                    if commonutils.isPermittedType(file):
                        objfile.set_unpacked_file(file)
        finally:
            # Temp-Folder loeschen
            shutil.rmtree(tmpdir)
            
        return objfile
