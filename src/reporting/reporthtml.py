# Copyright (C) 2013-2015 Ragpicker Developers.
# This file is part of Ragpicker Malware Crawler - http://code.google.com/p/malware-crawler/

import codecs
import logging
import os
import tempfile

from core.abstracts import Report
from core.commonutils import convertDirtyDict2ASCII
from core.constants import RAGPICKER_ROOT


try:
    from yapsy.IPlugin import IPlugin
except ImportError:
    raise ImportError, 'Yapsy (Yet Another Plugin System) is required to run this program: http://yapsy.sourceforge.net'

try:
    from jinja2.loaders import FileSystemLoader
    from jinja2.environment import Environment
except ImportError:
    raise ImportError("Jinja2 Python library is required to generate HTML reports: http://jinja.pocoo.org")

log = logging.getLogger(__name__)

class ReportHTML(IPlugin, Report):
    """Save report in HTML format."""
    
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
            jfile = url_md5 + "_" + file_md5 + ".html"
            
            if not os.path.exists(dumpdir + jfile):
                try:
                    env = Environment(autoescape=True)
                    env.loader = FileSystemLoader(os.path.join(RAGPICKER_ROOT, "data", "html"))
                    template = env.get_template("report.html")
                    reporthtml = template.render({"results" : results})
                except UnicodeDecodeError:
                    reporthtml = template.render({"results" : convertDirtyDict2ASCII(results)})
                except Exception as e:
                    raise Exception("Failed to generate HTML report: %s" % e)
                        
                try:
                    reportfile = codecs.open(os.path.join(dumpdir, jfile), "w", "utf-8")
                    reportfile.write(reporthtml)
                    reportfile.close()
                except (TypeError, IOError) as e:
                    raise Exception("Failed to write HTML report: %s" % e)      
