# Copyright (C) 2013-2015 Ragpicker Developers.
# This file is part of Ragpicker Malware Crawler - http://code.google.com/p/malware-crawler/

import StringIO
import logging
import re
import sys

from core.abstracts import Processing


try:
    from hachoir_subfile.search import SearchSubfile
    from hachoir_core.stream import FileInputStream
    from hachoir_core.cmd_line import unicodeFilename
except ImportError:
    raise ImportError, 'hachoir-subfile is required to run this program : http://bitbucket.org/haypo/hachoir/wiki/hachoir-subfile'

try:
    from yapsy.IPlugin import IPlugin
except ImportError:
    raise ImportError, 'Yapsy (Yet Another Plugin System) is required to run this program : http://yapsy.sourceforge.net'

log = logging.getLogger("ProcessingSubFile")

class subFile(IPlugin, Processing):
    
    def run(self, objfile):
        self.key = "SubFile"
        self.score = -1
        # Dictionary containing all the results of this processing.
        results = {}   
        
        try:
            results = self.subfile(objfile.file.temp_file)
        except (Exception) as e:
            log.error("The module \"SubFile\" returned the following error: %s" % e)   
            
        return results
        
    def subfile(self, filePath):
        # hachoir-subfile is a tool based on hachoir-parser to find subfiles in any binary stream.
        # Website: http://bitbucket.org/haypo/hachoir/wiki/hachoir-subfile
        # bypass sys.stdout, sys.stderr
        oldStdOut = sys.stdout
        oldStdErr = sys.stderr
        outputStdErr = StringIO.StringIO()
        outputStdOut = StringIO.StringIO()
        sys.stdout = outputStdOut
        sys.stderr = outputStdErr
        
        stream = FileInputStream(unicodeFilename(filePath), real_filename=filePath)
        
        # Search for subfiles
        subfile = SearchSubfile(stream, 0, None)
        subfile.loadParsers(categories=None, parser_ids=None)
        subfile.main()
        
        # sys.stdout, sys.stderr reset
        sys.stdout = oldStdOut
        sys.stderr = oldStdErr
    
        # parse stdout, stderr from SearchSubfile
        return self.parse(outputStdOut.getvalue(), outputStdErr.getvalue()) 
    
    def parse(self, stdout, stderr):   
        results = {}
        if stderr:
            if not len(stderr.split('\n')) <= 1:
                ret = []
                line = stderr.split('\n')
                for l in line:
                    if len(l) > 0: ret.append(l) 
                results["Errors"] = ret
        if stdout:
            if not len(stdout.split('\n')) <= 2:
                ret = []
                line = stdout.split('\n')
                for l in line:
                    if not re.findall('File at 0 size=', l):
                        subfile = l.replace("[+] ", "").split(': ')
                        if len(subfile) > 1:
                            sFile = {}
                            sFile["FileType"] = subfile[1]
                            sFile["Desc"] = subfile[0]
                            ret.append(sFile)
                results["Files"] = ret 
                        
            return results
