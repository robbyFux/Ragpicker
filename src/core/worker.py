# Copyright (C) 2013-2015 Ragpicker Developers.
# This file is part of Ragpicker Malware Crawler - http://code.google.com/p/malware-crawler/

from urlparse import urlparse
import datetime
import logging
import multiprocessing
import os
import socket
import urllib2

from core.database import Database
from core.config import Config
from core.constants import RAGPICKER_ROOT
from core.objfile import ObjFile
import core.commonutils as commonutils

try:
    from yapsy.PluginManager import PluginManager
except ImportError:
    raise ImportError, 'Yapsy (Yet Another Plugin System) is required to run this program : http://yapsy.sourceforge.net'

YARA_RULEPATH = "./data/index_result.yar"
log = logging.getLogger(__name__)

class Worker():
 
    def __init__(self):
        self.totalScore = 0  # sum of scores
        self.numberScores = 0  # number of scores entered
        self.processName = multiprocessing.current_process().name
        self.task = dict()
        self.cfgPreProcessing = Config(os.path.join(RAGPICKER_ROOT, 'config', 'preProcessing.conf'))
        self.cfgProcessing = Config(os.path.join(RAGPICKER_ROOT, 'config', 'processing.conf'))
        self.cfgReporting = Config(os.path.join(RAGPICKER_ROOT, 'config', 'reporting.conf'))
        self.cfgCrawler = Config(os.path.join(RAGPICKER_ROOT, 'config', 'crawler.conf'))
        self.database = Database()
        log.info("INIT " + self.processName)
 
    def run(self, url):
        # URLs not being processing
        if not self.__check_urlBlackList(url):
            try:
                objfile = ObjFile(url)                    
                # Zeitmessung Start
                self.task.update({"started_on":datetime.datetime.now()})
    
                # Download the file
                objfile = self.__process_url(url)
                
                # Permittet Type and file must be processed
                if objfile.file.is_permittedType() and self.isFileToProcess(objfile):
                    # PreProcessing e.g. unpacking
                    objfile = self.__run_preProcessing(objfile)
                    
                    # Run processing-plugins
                    results = self.__run_processing(objfile)
                    
                    if results:
                        log.debug(results)     
                        # Run Yara on results
                        yaraHits = self.__runYara(results)
                        
                        if yaraHits:
                            results.update(yaraHits)
                             
                        # Run report-plugins                     
                        self.__run_reporting(results, objfile)         
                elif not objfile.file.is_permittedType():
                    log.warn("url %s does not provide any allowed file type (%s)" % (url, objfile.file.get_type()))
            except urllib2.HTTPError as e:
                log.warn("Unable to perform HTTP request (http code=%s)" % e)
            except urllib2.URLError as e:    
                log.warn("Unable to establish connection: %s" % e)  
            except IOError as e:
                log.warn("Unable to establish connection: %s" % e) 
            except Exception, e:
                import traceback
                log.warn(traceback.print_exc())
                log.warn("Thread(" + self.processName + ") - %s - Error parsing %s" % (e, url))
            finally:   
                if objfile:
                    # File object close
                    objfile.close()    
                    
    def isFileToProcess(self, objfile):
        # Check RagpickerDatbase is enabled
        if not self.database.isRagpickerDBEnabled():
            return True
        
        # Process the file?
        if objfile.get_url_protocol() == "file":
            count = self.database.countRagpickerDB(objfile.file.get_fileMd5())             
        else:
            count = self.database.countRagpickerDB(objfile.file.get_fileMd5(), objfile.get_urlMd5())
            
        if count > 0:
            return False
        else:
            return True
    
    def runDelete(self):
        # Run report-plugins to delete all stored reporting data 
        self.__run_deleteAll()
        
    def __runYara(self, results):
        # Check Yara Support
        try:
            import yara
        except ImportError:
            return None
        
        yaraHits = commonutils.processYara(YARA_RULEPATH, data=str(results))

        # concatenate yarahits from sample file and result
        if results.get('Yara'):
            yaraHits = yaraHits + results['Yara']
            
        if yaraHits:
            yaraHits = {"Yara" : yaraHits}
        
        return yaraHits
            
    def __check_urlBlackList(self, url):
        
        try:
            urlBlackList = self.cfgCrawler.get('urlBlackList')
        except Exception:
            log.error("urlBlackList not found in configuration file")
            return 

        urls = map(lambda s: s.strip('\''), urlBlackList.get('url').split(','))
        
        o = urlparse(url)
        hostname = o.hostname

        if hostname in urls:
            log.info("%s in Url-BlackList: %s" % (hostname, urls))
            return True
            
        return False
    
    def __run_reporting_generator(self):
                
        # options
        options = dict()
        
        # Build the PluginManager
        reportingPluginManager = PluginManager()
        reportingPluginManager.setPluginPlaces(["reporting"])
        reportingPluginManager.collectPlugins()
        
        # Trigger run from the "Reporting" plugins
        for pluginInfo in sorted(reportingPluginManager.getAllPlugins(), key=lambda PluginInfo: PluginInfo.name):
            reportingModulG = pluginInfo.plugin_object
            reportingModulG.set_task(self.task)
            
            # Give it the the relevant reporting.conf section.
            try:
                options = self.cfgReporting.get(pluginInfo.name)
                reportingModulG.set_options(options)
            except Exception:
                log.error("Reporting module %s not found in configuration file", pluginInfo.name)  
                
            # If the processing module is disabled in the config, skip it.
            if not options.enabled:
                continue
            
            log.debug("Run Reporting: " + pluginInfo.name)
            
            yield reportingModulG
            
    def __run_reporting(self, results, objfile):
        
        for reportingModul in self.__run_reporting_generator():
            
            try:
                # Run the Reporting module
                reportingModul.run(results, objfile)
            except Exception as e:
                log.exception("Failed to run the reporting module \"%s\":", reportingModul.__class__.__name__)
                
    def __run_deleteAll(self):
        # Run report-plugins to delete all stored reporting data 
        
        for reportingModul in self.__run_reporting_generator():
            
            try:
                # Run the Reporting module
                reportingModul.deleteAll()
            except Exception as e:
                log.exception("Failed to run the reporting module \"%s\":", reportingModul.__class__.__name__)            
            
    def __run_preProcessing(self, objfile):
        # options
        options = dict()
        
        # Build the PluginManager
        processPluginManager = PluginManager()
        processPluginManager.setPluginPlaces(["preProcessing"])
        processPluginManager.collectPlugins()
        
        # Trigger run from the "Processing" plugins
        for pluginInfo in sorted(processPluginManager.getAllPlugins(), key=lambda PluginInfo: PluginInfo.name):
            processModul = pluginInfo.plugin_object
            
            # Config for processing module
            try:
                options = self.cfgPreProcessing.get(pluginInfo.name)
                processModul.set_options(options)
                processModul.set_task(self.task)
            except Exception:
                log.error("preProcessing module %s not found in configuration file", pluginInfo.name)  
                
            # If the processing module is disabled in the config, skip it.
            if not options.enabled:
                continue
            # Check allowable data type
            if options.datatypes and not objfile.file.get_type() in options.datatypes:
                continue
            
            log.debug("Run preProcessing: " + pluginInfo.name)
            
            try:
                # Run the processing module and retrieve the generated data to be
                # appended to the general results container.
                objfile = processModul.run(objfile)
            except Exception as e:
                log.exception("Failed to run the preProcessing module \"%s\":",
                              processModul.__class__.__name__)
            
        return objfile
            
    def __run_processing(self, objfile):
        # This is the results container. It's what will be used by all the
        # reporting modules to make it consumable by humans and machines.
        # It will contain all the results generated by every processing
        # module available. Its structure can be observed throgh the JSON
        # dump in the the analysis' reports folder.
        # We friendly call this "fat dict".
        results = {}
        # options
        options = dict()
        
        # Build the PluginManager
        processPluginManager = PluginManager()
        processPluginManager.setPluginPlaces(["processing"])
        processPluginManager.collectPlugins()
        
        # Trigger run from the "Processing" plugins
        for pluginInfo in sorted(processPluginManager.getAllPlugins(), key=lambda PluginInfo: PluginInfo.name):
            processModul = pluginInfo.plugin_object
            
            # Config for processing module
            try:
                options = self.cfgProcessing.get(pluginInfo.name)
                processModul.set_options(options)
                processModul.set_task(self.task)
            except Exception:
                log.error("Processing module %s not found in configuration file", pluginInfo.name)  
                
            # If the processing module is disabled in the config, skip it.
            if not options.enabled:
                continue
            # Check allowable data type
            if options.datatypes and not objfile.file.get_type() in options.datatypes:
                continue
            
            log.debug("Run Processing: " + pluginInfo.name)
           
            try:
                # Run the processing module and retrieve the generated data to be
                # appended to the general results container.
                data = processModul.run(objfile)
    
                # If it provided some results, append it to the big results
                # container.
                if data:
                    results.update({processModul.key : data})
                    
                # set scoring from processModul
                if processModul.score > -1:
                    log.debug("Score %s: %s" % (pluginInfo.name, str(processModul.score)))
                    self._setScore(processModul.score)
            except Exception as e:
                log.exception("Failed to run the processing module \"%s\":",
                              processModul.__class__.__name__)
        
        # calculate scoring
        scoring = self._getScoring()
        results.update({"score" : scoring})
        log.debug("SCORING: " + scoring)
        
        return results
 
    def __process_url(self, url):
        # Crawler config load
        cfgCrawler = Config(os.path.join(RAGPICKER_ROOT, 'config', 'crawler.conf')).get("clientConfig")
        
        data = None
        headers = {   
            'User-Agent': cfgCrawler.get("browser_user_agent", "Mozilla/4.0 (compatible; MSIE 5.5; Windows NT)"),
            'Accept-Language': cfgCrawler.get("browser_accept_language", "en-US"),
        }
        
        # Save original socket
        originalSocket = socket.socket
        # Set TOR Socks proxy
        commonutils.setTorProxy() 
               
        request = urllib2.Request(url, data, headers)
    
        try:
            url_dl = urllib2.urlopen(request, timeout=30).read()
        except urllib2.HTTPError as e:
            raise e
        except urllib2.URLError as e:    
            raise e
        except Exception, e:
            raise IOError("Thread(" + self.processName + ") - %s - Error parsing %s" % (e, url)) 
        finally:
            # Removing SOCKS Tor Proxy 
            socket.socket = originalSocket 
            
        log.info("Download from URL %s" % url)
        
        try:
            objfile = ObjFile(url)
            objfile.set_file_from_stream(url_dl)
        except Exception, e:
            raise Exception("Thread(" + self.processName + ") - %s - Error create ObjFile %s" % (e, url)) 
 
        return objfile
    
    def _setScore(self, score):
        self.totalScore = self.totalScore + score
        self.numberScores = self.numberScores + 1
        
    def _getScoring(self):
        if self.numberScores != 0:  # division by zero would be a run-time error
            average = float(self.totalScore) / self.numberScores
            average = round(average, 1)
        else:
            # No scores were entered
            average = 0
           
        return str(average)
