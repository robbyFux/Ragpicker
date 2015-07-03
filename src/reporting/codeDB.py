# Copyright (C) 2013-2015 Ragpicker Developers.
# This file is part of Ragpicker Malware Crawler - http://code.google.com/p/malware-crawler/

import base64
import json
import logging
import os
import tempfile
import time
import urllib2

from core.database import Database
from core.abstracts import Report
from core.commonutils import convertDirtyDict2ASCII
from core.commonutils import flatten_dict
from utils.codeDBobjects import VOMalwareSample

try:
    from yapsy.IPlugin import IPlugin
except ImportError:
    raise ImportError, 'Yapsy (Yet Another Plugin System) is required to run this program : http://yapsy.sourceforge.net'

log = logging.getLogger("ReportingCodeDB")

CODE_DB_URL_SCAN_ONLY = "https://%s:%s/sample/do_scanOnly"
CODE_DB_URL_ADD = "https://%s:%s/sample/add"
CODE_DB_URL_STATUS = "https://%s:%s/sample/status/json/%s"
CODE_DB_URL_IMAGE = "https://%s:%s/image/get/%s"
CODE_DB_URL_REPORT = "https://%s:%s/sample/get/json/%s"
TIME_OUT = 240
VERTRAULICH_FREIGEGEBEN = "0"
# Status eines Samples
ERROR = "-1"
NOT_EXISTS = "0"
PENDING = "1"
BEING_PROCESSED = "2"
FINISHED = "3"
KLONE = "4"
FAMILY = "5"
PROCESSING_STATE_FINISHED = "finished"
ERROR_BAD_SHA256 = "Error: bad or missing sha256"
# Bild 
CONTENT_TYPE_PNG = "image/png"

class CodeDB(IPlugin, Report):
    
    def setConfig(self):
        self.headers = {}
        self.cfg_host = self.options.get("host")
        self.cfg_port = self.options.get("port")
        cfg_user = self.options.get("user")
        cfg_password = self.options.get("password") 
        # Config fuer Images
        self.cfg_downloadImages = self.options.get("save_images")
        self.cfg_dumpdir = self.options.get("dumpdir") 
        # Config fuer Reports
        self.cfg_saveReports = self.options.get("save_reports")
        self.cfg_mongoHost = self.options.get("mongo_db_host")
        self.cfg_mongoPort = self.options.get("mongo_db_port")
        
        if not self.cfg_host or not self.cfg_port:
            raise Exception("CodeDB REST API-Server not configurated")
        
        if self.cfg_downloadImages and not self.cfg_dumpdir:
            raise Exception("CodeDB not configured correctly: cfg_dumpdir")
        
        if self.cfg_saveReports and not (self.cfg_mongoHost and self.cfg_mongoPort):
            raise Exception("CodeDB not configured correctly: MongoDB")
        
        if cfg_user and cfg_password:
            self.headers = {"Authorization" : "Basic %s" % base64.encodestring("%s:%s" % (cfg_user, cfg_password)).replace('\n', '')}

    def run(self, results, objfile):
        self.key = "CodeDB"
        # Konfiguration setzen
        self.setConfig() 
        
        # Save file
        self.processCodeDB(results, objfile, objfile.file)
        
        # Save unpacked file
        if objfile.unpacked_file:
            self.processCodeDB(results, objfile, objfile.unpacked_file, unpacked=True)
            
        # Save included files
        if len(objfile.included_files) > 0:
            log.info("Save included files")
            for incl_file in objfile.included_files:
                self.processCodeDB(results, objfile, incl_file, extracted=True)
        
    def processCodeDB(self, results, objfile, file, unpacked=False, extracted=False):
        status = self._getFileStatus(file.get_fileSha256())
        value = status.get("value")
        processingState = status.get("processingState")
        
        # Sample schon in der CodeDB vorhanden ggf. Image und Report laden
        if value == FINISHED and processingState == PROCESSING_STATE_FINISHED:
            if self.cfg_downloadImages:
                # Sample schon vorhanden -> Bild laden
                self._saveImage(file.get_fileSha256(), self.cfg_dumpdir)
            if self.cfg_saveReports:  # Sample schon vorhanden -> Save Report
                self._saveReportInMongoDB(file.get_fileSha256())
    
        # Sample in CodeDB nicht vorhanden und nach simpler Pruefung hochladbar -> Analyse durch CodeDB
        if value == NOT_EXISTS and (unpacked or extracted or self._isFileUploadable(results)):
            # Datei hochladbar und nicht vorhanden -> hinzufuegen
            uploadStatus = self._addFile(results, objfile, file, unpacked, extracted)
            # CodeDB liefert bei erfolgreichem Upload den SHA256 Hash zurueck
            if uploadStatus and uploadStatus.get("Submitted") == file.get_fileSha256():
                # Sollen Bilder geladen werden und ist ein Bild vorhanden?
                if self.cfg_downloadImages and self._isDataLoadable(file.get_fileSha256()):
                    # Bild laden
                    self._saveImage(file.get_fileSha256(), self.cfg_dumpdir)  # Soll der Report gespeichert werden und ist nicht bereits vorhanden?
                if self.cfg_saveReports and self._isDataLoadable(file.get_fileSha256()):
                    # Report in MongoDB speichern
                    self._saveReportInMongoDB(file.get_fileSha256())
            else:
                # Falscher Status oder SHA256-Hash stimmt nicht
                raise Exception("CodeDB Uploaderror: %s" % uploadStatus)

    def _addFile(self, results, objfile, file, unpacked, extracted):
        # rawFile = open(file.temp_file, 'rb')
        log.info("_addFile: " + CODE_DB_URL_ADD % (self.cfg_host, self.cfg_port))
        voCodeDB = VOMalwareSample()
        
        try:                            
            voCodeDB.setsha256(file.get_fileSha256())
            
            if unpacked:
                # Bei entpackten Samples wird der Orighash gespeichert
                voCodeDB.setOrighash(objfile.file.get_fileSha256())
            
            voCodeDB.setVertraulich(VERTRAULICH_FREIGEGEBEN)
            voCodeDB.setFileName(convertDirtyDict2ASCII(objfile.get_url_filename()))
            
            info = results.get("Info")
            
            # Ist Datei exe, dll, sys?
            if(info.get("file").get("EXE") == True):
                voCodeDB.setbinType("exe")
            elif(info.get("file").get("DLL") == True):
                voCodeDB.setbinType("dll")
            elif(info.get("file").get("DRIVER") == True):
                voCodeDB.setbinType("sys")
                
            voCodeDB.setDownloadDatestamp(info.get("analyse").get("started").strftime("%Y-%m-%d %H:%M"))
            voCodeDB.setDownloadHostname(convertDirtyDict2ASCII(info.get("url").get("hostname")))
            
            # Felder nicht zwingend vorhanden
            if "OwnLocation" in results:    
                ownLocation = results.get('OwnLocation')
                voCodeDB.setGeolocationSelf(ownLocation.get("country"))
                
            # GeolocationHost nur vorhanden wenn InetSourceAnalysis benutzt wird
            if results.has_key('InetSourceAnalysis') and results.get('InetSourceAnalysis').has_key('URLVoid'):
                urlResult = results.get('InetSourceAnalysis').get('URLVoid').get('urlResult')
                voCodeDB.setGeolocationHost(urlResult.get('CountryCode'))
                voCodeDB.setDownloadIP(urlResult.get("IP"))                

            voCodeDB.setTags(self._getTags(results, objfile, unpacked, extracted))
            # Debug Ausgabe
            voCodeDB.prints()
            
            # Upload File to CodeDB
            uploadStatus = self._upload(convertDirtyDict2ASCII(objfile.get_url_filename()), file.file_data, voCodeDB)
        
            return uploadStatus
                
        except urllib2.URLError as e:
            raise Exception("Unable to establish connection to CodeDB REST API-Server server: %s" % e)
        except urllib2.HTTPError as e:
            raise Exception("Unable to perform HTTP request to CodeDB REST API-Server (http code=%s)" % e)        
    
    def _upload(self, url_filename, file_data, voCodeDB):
        for i in range(3): 
            # Formular erstellen  
                      
            try:
                form = voCodeDB.toMultiPartForm()
                form.add_file_data(fieldname='sample', filename=url_filename, file_data=file_data)
                request = urllib2.Request(CODE_DB_URL_ADD % (self.cfg_host, self.cfg_port), headers=self.headers)
                body = str(form)
            except UnicodeDecodeError as e:
                log.info("UnicodeDecodeError - fallback to base64")
                voCodeDB.setBase64("True")
                form = voCodeDB.toMultiPartForm()
                form.add_file_data_b64(fieldname='sample', filename=url_filename, file_data=file_data)
                request = urllib2.Request(CODE_DB_URL_ADD % (self.cfg_host, self.cfg_port), headers=self.headers)
                body = str(form)
            
            request.add_header('Content-type', form.get_content_type())
            request.add_header('Content-length', len(body))
            request.add_data(body)
            response_data = urllib2.urlopen(request, timeout=TIME_OUT).read()
            log.info("_addFile: " + str(response_data))
            uploadStatus = self.json2dic(response_data)
            
            if uploadStatus.get("Status") and ERROR_BAD_SHA256 in uploadStatus.get("Status"):
                log.warning("Bad SHA256, Fehlerhafter Upload!")
            else:
                log.info(uploadStatus)
                return uploadStatus
        
        return uploadStatus
    
    def _getTags(self, results, objfile, unpacked, extracted):
        tags = {}
        resultsFile = results.get("Info").get("file")
        
        tags["Collector"] = "Ragpicker"
        
        # Antivirus is no longer used
        #for k, v in results.items():
        #    if "Antivirus" in k:
        #        tags.update(flatten_dict(v))
        
        # Analyse-UUID
        tags["Ragpicker-uuid"] = results.get("Info").get("analyse").get("uuid")
        
        # Special hashes
        if resultsFile.get("pehash"):
            tags["PEHash"] = resultsFile.get("pehash")
        if resultsFile.get("imphash"):
            tags["ImpHash"] = resultsFile.get("imphash")
        
        if extracted:
            tags["OrigFileType"] = objfile.file.get_type()
            tags["ExtractedFrom"] = objfile.file.get_fileSha256()
        if unpacked:
            tags["OrigFileType"] = objfile.file.get_type()
            
        # PE-File CPU, Subsystem, Architecture
        if resultsFile.get("Subsystem"):
            tags["Subsystem"] = resultsFile.get("Subsystem")        
        if resultsFile.get("Architecture"):
            tags["Architecture"] = resultsFile.get("Architecture") 
        if resultsFile.get("CPU"):
            tags["CPU"] = resultsFile.get("CPU") 
                                    
        if not unpacked or not extracted:
            # Digital Signature
            try:
                if resultsFile.has_key("digitalSignature"):
                    tags["DigitalSignature"] = results.get("Info").get("file").get("digitalSignature")
            except KeyError:
                # Key is not present
                pass
            
            try:
                if results.has_key("VerifySigs"):
                    if "ValidationError" in results.get("VerifySigs"):
                        tags["ValidationError"] = results.get("VerifySigs").get("ValidationError")
                    else:
                        tags.update(flatten_dict(results.get("VerifySigs")))
            except KeyError:
                # Key is not present
                pass
            
            if results.has_key("PEID"):
                tags["PEID"] = results.get("PEID")[0]
                
            if results.has_key("Teamcymru"): 
                tags["Teamcymru"] = "malwarepercent=%s" % results.get("Teamcymru").get("malwarepercent")
                
            # VirusTotal
            try:
                if results.has_key("VirusTotal") and results.get("VirusTotal").has_key("file"):
                    vtFile = results.get("VirusTotal").get("file")
                    s = "%s/%s" % (vtFile.get("positives"), vtFile.get("total"))
                    tags["VirusTotal"] = s
                    
                    if vtFile.has_key("scannerMalwareFamily"):
                        family = vtFile.get("scannerMalwareFamily")
                        tags["AvScannerMalwareFamily"] = "%s (count=%s)" % (family.get("family"), family.get("count"))
                        
            except KeyError:
                # Key is not present
                pass
            
        #clean tags
        for k in tags: 
            tags[k] = convertDirtyDict2ASCII(tags[k])
        
        log.debug(tags)
        
        return tags    
    
    # Pruefung ob Daten von der CodeDB geladen werden koennen
    def _isDataLoadable(self, sha256):        
        for i in range(20): 
            status = self._getFileStatus(sha256)
            value = status.get("value")
            processingState = status.get("processingState")
            
            if value == FAMILY or value == KLONE:
                log.warning("------------------------------- " + value + " : " + processingState)
                return False            
            if value == FINISHED and processingState == PROCESSING_STATE_FINISHED:
                # Fein wir koennen das Image laden 
                return True
            if value == FINISHED and processingState != PROCESSING_STATE_FINISHED:
                # Kein Bild vorhanden :( Ursache z.B. "In bad list with reason: packed"
                log.warning("Can not load image from CodeDB: %s" % processingState) 
                return False
            elif value == PENDING or value == BEING_PROCESSED:
                # Hier muessen wir noch ein wenig warten
                log.info("%d Sleep ..." % i)
                time.sleep(6)
            elif value == NOT_EXISTS or value == ERROR:
                # Fehlerfall
                raise Exception("CodeDB Error LoadImage Status: %s" % status)
            else:
                # Fehlerfall
                raise Exception("CodeDB Error LoadImage Status unknown: %s" % status)

        # Scheint nicht zu klappen :(
        return False
    
    def _saveReportInMongoDB(self, sha256):
        database = Database()
        count = database.countCodeDB(sha256)
        
        # If report available for the file and url -> not insert
        if count == 0:
            # GetReport from CodeDB by HTTPS
            report = self._getCodeDBReport(sha256)
            
            # Create a copy of the dictionary. This is done in order to not modify
            # the original dictionary and possibly compromise the following
            # reporting modules.
            report = dict(report)
            # Store the report and retrieve its object id.
            database.insertCodeDB(report)
            log.info("Saved CodeDB-Report %s" % sha256)
  
    def _getCodeDBReport(self, sha256):
        log.debug(CODE_DB_URL_REPORT % (self.cfg_host, self.cfg_port, sha256))
        
        try:
            request = urllib2.Request(CODE_DB_URL_REPORT % (self.cfg_host, self.cfg_port, sha256), headers=self.headers)
            result = urllib2.urlopen(request, timeout=60)
            response_data = result.read()   
        except urllib2.HTTPError as e:
            raise Exception("Unable to perform HTTP request to CodeDB (http code=%s)" % e)
        except urllib2.URLError as e:    
            raise Exception("Unable to establish connection to CodeDB: %s" % e)  
        
        report = self.json2dic(response_data)
        
        log.debug("_getCodeDBReport: " + str(report))
        
        if report.get("Status") and "Error" in report.get("Status"):
            log.error("CodeDB return State: %s" % report.get("Status"))
            raise Exception("CodeDB return State: %s" % report.get("Status"))
    
        return report       
    
    def _saveImage(self, sha256, dumpdir):
        # PNG-File erzeugen
        filePath = dumpdir + "/" + sha256 + ".png"
        
        # DumpDir pruefen
        self.checkDumpdir(dumpdir)
        
        # Pruefen ob das Bild schon vorhanden ist 
        if os.path.isfile(filePath):
            log.info("Image file already exists. Pass")
            return filePath

        try:
            request = urllib2.Request(CODE_DB_URL_IMAGE % (self.cfg_host, self.cfg_port, sha256), headers=self.headers)
            result = urllib2.urlopen(request, timeout=60)
            
            # Bekommen wir wirklich ein PNG-Bild zurueck?
            if result.info().getheader('Content-Type') != CONTENT_TYPE_PNG: 
                raise Exception("Unable to load image, wrong Content-Type: %s" % result.info().getheader('Content-Type'))
            
            response_data = result.read()   
        except urllib2.HTTPError as e:
            raise Exception("Unable to perform HTTP request to CodeDB (http code=%s)" % e)
        except urllib2.URLError as e:    
            raise Exception("Unable to establish connection to CodeDB: %s" % e)  
        
        # PNG-File schreiben
        if not os.path.exists(filePath):
            file = open(filePath, 'wb')
            file.write(response_data)
            file.close
            log.info("Saved CodeDB-Image %s" % filePath)
    
        return filePath

    def _getFileStatus(self, sha256):
        log.debug(CODE_DB_URL_STATUS % (self.cfg_host, self.cfg_port, sha256))
        
        try:
            request = urllib2.Request(CODE_DB_URL_STATUS % (self.cfg_host, self.cfg_port, sha256), headers=self.headers)
            result = urllib2.urlopen(request, timeout=60)
            response_data = result.read()   
        except urllib2.HTTPError as e:
            log.error("getFileStatus: " + CODE_DB_URL_STATUS % (self.cfg_host, self.cfg_port, sha256))
            raise Exception("Unable to perform HTTP request to CodeDB (http code=%s)" % e)
        except urllib2.URLError as e:    
            raise Exception("Unable to establish connection to CodeDB: %s" % e)  
        
        check = self.json2dic(response_data)
        
        log.info("_getFileStatus: " + str(check))
        
        if check.get("value") == ERROR :
            log.error("CodeDB return State: %s - Value: %s" % (check.get("Status"), check.get("value")))
            raise Exception("CodeDB return State: %s - Value: %s" % (check.get("Status"), check.get("value")))
    
        return check       
    
    def _isFileUploadable(self, results):
        fileInfo = results.get("Info").get("file")
                
        if fileInfo.has_key("isProbablyPacked") and fileInfo.has_key("EXE") and fileInfo.has_key("DLL") \
        and fileInfo.get("isProbablyPacked") == False:
            return True
    
        return False
    
    def json2dic(self, data):
        try:
            dic = json.loads(data)
        except ValueError as e:
            raise Exception("Unable to convert response to JSON: %s" % e)
        return dic
    
    def checkDumpdir(self, dumpdir):
        try:
            if not os.path.exists(dumpdir):
                os.makedirs(dumpdir)
            d = tempfile.mkdtemp(dir=dumpdir)
        except Exception as e:
            raise Exception('Could not open %s for writing (%s)', dumpdir, e)
        else:
            os.rmdir(d)
            
    def deleteAll(self):  
        """Deletes all reports.
        """  
        count = Database().deleteCodeDB()
        
        print "*** MongoDB (CodeDB)***"
        print "deleted documents:" + str(count)
        print ""
