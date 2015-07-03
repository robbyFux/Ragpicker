# Copyright (C) 2013-2015 Ragpicker Developers.
# This file is part of Ragpicker Malware Crawler - http://code.google.com/p/malware-crawler/

import codecs
import datetime
import jsonpickle
import logging
import os
import tempfile
import uuid

from core.abstracts import Report
from core.commonutils import DatetimeHandler
from core.commonutils import UUIDHandler
from core.commonutils import convertDirtyDict2ASCII


try:
    from yapsy.IPlugin import IPlugin
except ImportError:
    raise ImportError, 'Yapsy (Yet Another Plugin System) is required to run this program : http://yapsy.sourceforge.net'

log = logging.getLogger(__name__)

class JsonDump(IPlugin, Report):
    """Saves analysis results in JSON format."""
    
    def run(self, results, objfile):
        """Writes report.
        @param results: results dict.
        @param objfile: file object
        @raise Exception: if fails to write report.
        """
        dumpdir = self.options.get("dumpdir", None)

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
        
        url_md5 = results["Info"]["url"]["md5"]
        file_md5 = results["Info"]["file"]["md5"]
        jfile = url_md5 + "_" + file_md5 + ".json"

        try:
            jsonpickle.set_encoder_options('simplejson', indent=4) 
            jsonpickle.handlers.registry.register(datetime.datetime, DatetimeHandler)
            jsonpickle.handlers.registry.register(uuid.UUID, UUIDHandler)
            jsonReport = jsonpickle.encode(results)
        except (UnicodeError, TypeError):
            jsonReport = jsonpickle.encode(convertDirtyDict2ASCII(results))
        
        try:  
            if not os.path.exists(dumpdir + jfile):
                report = codecs.open(os.path.join(dumpdir, jfile), "w", "utf-8")      
                report.write(jsonReport)
                report.close()
        except (TypeError, IOError) as e:
            raise Exception("Failed to generate JSON report: %s" % e)    
