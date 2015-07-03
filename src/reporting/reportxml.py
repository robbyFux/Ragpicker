# Copyright (C) 2013-2015 Ragpicker Developers.
# This file is part of Ragpicker Malware Crawler - http://code.google.com/p/malware-crawler/
# coding: utf-8

import codecs
import logging
import os
import tempfile

from core.abstracts import Report
from core.commonutils import convertDirtyDict2ASCII
import utils.dict2xml as dict2xml


try:
    from yapsy.IPlugin import IPlugin
except ImportError:
    raise ImportError, 'Yapsy (Yet Another Plugin System) is required to run this program: http://yapsy.sourceforge.net'

log = logging.getLogger(__name__)

class ReportXML(IPlugin, Report):
    """Save report in XML format."""
    
    def run(self, results, objfile):
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
            jfile = url_md5 + "_" + file_md5 + ".xml"
            
            if not os.path.exists(dumpdir + jfile):
                try:
                    reportxml = dict2xml.dicttoxml(results)
                except UnicodeDecodeError:
                    reportxml = dict2xml.dicttoxml(convertDirtyDict2ASCII(results))
                except Exception as e:
                    raise Exception("Failed to generate XML report: %s" % e)
                        
                try:
                    
                    reportfile = codecs.open(os.path.join(dumpdir, jfile), "w", "utf-8")
                    reportfile.write(reportxml)
                    reportfile.close()
                except (TypeError, IOError) as e:
                    raise Exception("Failed to write XML report: %s" % e)   
   
