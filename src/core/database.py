# Copyright (C) 2013-2015 Ragpicker Developers.
# This file is part of Ragpicker Malware Crawler - http://code.google.com/p/malware-crawler/

import os
import logging
from core.commonutils import convertDirtyDict2ASCII
from core.config import Config
from core.constants import RAGPICKER_ROOT

try:
    from pymongo.connection import Connection
    from pymongo.errors import ConnectionFailure, InvalidStringData, InvalidDocument
except ImportError:
    raise Exception("PyMongo is required for working with MongoDB: http://api.mongodb.org/python/current/")   

def singleton(class_):
    instances = {}
    def getinstance(*args, **kwargs):
        if class_ not in instances:
            instances[class_] = class_(*args, **kwargs)
        return instances[class_]
    return getinstance
  
log = logging.getLogger("Database")  
  
@singleton
class Database():

    def __init__(self):
        self.__cfgReporting = Config(os.path.join(RAGPICKER_ROOT, 'config', 'reporting.conf'))
        self.__cfgProcessing = Config(os.path.join(RAGPICKER_ROOT, 'config', 'processing.conf'))
        self.__mongodbEnabled = self.__cfgReporting.getOption("mongodb", "enabled")
        self.__codedbEnabled = self.__cfgReporting.getOption("codeDB", "enabled")
        self.__bluecoatEnabled = self.__cfgProcessing.getOption("all_bluecoatMalwareAnalysisAppliance", "enabled")
        
        if self.__mongodbEnabled:
            #Anbindung an Datenbank MongoDB Collection Ragpicker herstellen
            try:
                mongodbHost = self.__cfgReporting.getOption("mongodb", "host")
                mongodbPort = self.__cfgReporting.getOption("mongodb", "port")
                self.__mongodbConnection = Connection(mongodbHost, mongodbPort)
                self.__mongodbCollectionRagpicker = self.__mongodbConnection.MalwareAnalyse.ragpicker
                self.__mongodbCollectionFamilies = self.__mongodbConnection.MalwareAnalyse.families
                self.__mongodbCollectionSandboxTaskQueue = self.__mongodbConnection.MalwareAnalyse.sandboxTaskQueue
            except TypeError:
                raise Exception("MongoDB connection port in report.config must be integer")
            except ConnectionFailure:
                raise Exception("Cannot connect to MongoDB (ragpicker)")
        
        if self.__codedbEnabled:
            #Anbindung an Datenbank MongoDB Collection CodeDB herstellen
            try:
                codedbHost = self.__cfgReporting.getOption("codeDB", "mongo_db_host")
                codedbPort = self.__cfgReporting.getOption("codeDB", "mongo_db_port")
                self.__codedbConnection = Connection(codedbHost, codedbPort)
                self.__codedbCollectionCodedb = self.__codedbConnection.MalwareAnalyse.codeDB
            except TypeError:
                raise Exception("MongoDB connection port for CodeDB in report.config must be integer")
            except ConnectionFailure:
                raise Exception("Cannot connect to MongoDB (codeDB)")  

    def __del__(self):
        if self.__mongodbEnabled:
            self.__mongodbConnection.disconnect()
        if self.__codedbEnabled:
            self.__codedbConnection.disconnect()
    
# ------------------------------------------------------------------------------
# Ragpicker Database (MongoDB)
# ------------------------------------------------------------------------------    

    def isRagpickerDBEnabled(self):
        return self.__mongodbEnabled
    
    def getStatisticsAntivirus(self):
        queries = []
        ret = []
        queries.append({"product" : "Avast Antivirus", "findStr1" : "AntivirusScanAvast", "findStr2" : "AntivirusScanAvast.avast", "ok" : "OK"})
        queries.append({"product" : "AVG Antivirus", "findStr1" : "AntivirusScanAvg", "findStr2" : "AntivirusScanAvg.Avg", "ok" : "OK"})
        queries.append({"product" : "Avira", "findStr1" : "AntivirusScanAvira", "findStr2" : "AntivirusScanAvira.Avira.scan", "ok" : "OK"})
        queries.append({"product" : "BitDefender", "findStr1" : "AntivirusScanBitDefender", "findStr2" : "AntivirusScanBitDefender.BitDefender", "ok" : "OK"})
        queries.append({"product" : "ClamAV", "findStr1" : "AntivirusScanClamAv", "findStr2" : "AntivirusScanClamAv.ClamAv", "ok" : " OK"})        
        queries.append({"product" : "COMODO", "findStr1" : "AntivirusScanCOMODO", "findStr2" : "AntivirusScanCOMODO.COMODO", "ok" : "OK"})
        queries.append({"product" : "ESET", "findStr1" : "AntivirusScanESET", "findStr2" : "AntivirusScanESET.ESET", "ok" : "OK"})
        queries.append({"product" : "F-Prot", "findStr1" : "AntivirusScanFProt", "findStr2" : "AntivirusScanFProt.FProt", "ok" : "OK"})
        queries.append({"product" : "F-Secure", "findStr1" : "AntivirusScanF-Secure", "findStr2" : "AntivirusScanF-Secure.F-Secure", "ok" : "OK"})
        
        for q in queries:
            av = {}          
            av["product"] = q.get("product")
            av["analyzed"] = str(self.__mongodbCollectionRagpicker.find({q.get("findStr1"): {"$ne":None}}).count())
            av["notanalyzed"] = str(self.__mongodbCollectionRagpicker.find({q.get("findStr1") : None}).count())
            av["malware"] = str(self.__mongodbCollectionRagpicker.find({ "$and": [{q.get("findStr1") : {"$ne":None}}, {q.get("findStr2") : {"$ne": q.get("ok")}}]}).count())
            av["nonemalware"] = str(self.__mongodbCollectionRagpicker.find({q.get("findStr2"): q.get("ok")}).count())
            
            if av.get("analyzed") != "0":
                av["rate"] = "{:.2f} %".format((float(av.get("malware"))/float(av.get("analyzed"))*100)) 
            else:
                av["rate"] = "--"
                
            ret.append(av)
        
        return ret
    
    def getStatisticsNoneMalwareByAV(self):
        return self.__mongodbCollectionRagpicker.find({ "$and": [{ "$or": [{"AntivirusScanAvast.avast" : "OK"}, {"AntivirusScanAvast" : None}]},
                                                                 { "$or": [{"AntivirusScanAvg.Avg" : "OK"}, {"AntivirusScanAvg" : None}]},
                                                                 { "$or": [{"AntivirusScanAvira.Avira.scan" : "OK"}, {"AntivirusScanAvira" : None}]},
                                                                 { "$or": [{"AntivirusScanBitDefender.BitDefender" : "OK"}, {"AntivirusScanBitDefender" : None}]},
                                                                 { "$or": [{"AntivirusScanClamAv.ClamAv" : " OK"}, {"AntivirusScanClamAv" : None}]},
                                                                 { "$or": [{"AntivirusScanCOMODO.COMODO" : "OK"}, {"AntivirusScanCOMODO" : None}]},
                                                                 { "$or": [{"AntivirusScanESET.ESET" : "OK"}, {"AntivirusScanESET" : None}]},
                                                                 { "$or": [{"AntivirusScanFProt.FProt" : "OK"}, {"AntivirusScanFProt" : None}]},
                                                                 { "$or": [{"AntivirusScanF-Secure.F-Secure" : "OK"}, {"AntivirusScanF-Secure" : None}]},
                                                                 {"VirusTotal.file.verbose_msg" : {"$ne":None}}]}).count()
                                                                 
    def getSamplesNotFoundByAV(self):
        return self.__mongodbCollectionRagpicker.find({ "$and": [{ "$or": [{"AntivirusScanAvast.avast" : "OK"}, {"AntivirusScanAvast" : None}]},
                                                                 { "$or": [{"AntivirusScanAvg.Avg" : "OK"}, {"AntivirusScanAvg" : None}]},
                                                                 { "$or": [{"AntivirusScanAvira.Avira.scan" : "OK"}, {"AntivirusScanAvira" : None}]},
                                                                 { "$or": [{"AntivirusScanBitDefender.BitDefender" : "OK"}, {"AntivirusScanBitDefender" : None}]},
                                                                 { "$or": [{"AntivirusScanClamAv.ClamAv" : " OK"}, {"AntivirusScanClamAv" : None}]},
                                                                 { "$or": [{"AntivirusScanCOMODO.COMODO" : "OK"}, {"AntivirusScanCOMODO" : None}]},
                                                                 { "$or": [{"AntivirusScanESET.ESET" : "OK"}, {"AntivirusScanESET" : None}]},
                                                                 { "$or": [{"AntivirusScanFProt.FProt" : "OK"}, {"AntivirusScanFProt" : None}]},
                                                                 { "$or": [{"AntivirusScanF-Secure.F-Secure" : "OK"}, {"AntivirusScanF-Secure" : None}]},
                                                                 {"VirusTotal.file.verbose_msg" : {"$ne":None}}
                                                                 ]}, {"Info.file.sha256": True, "Info.analyse.started": True })
                                                        
    def getSamplesNotFoundByVT(self):
        return self.__mongodbCollectionRagpicker.find({"VirusTotal.file.verbose_msg" : {"$ne":None}}, {"Info.file.sha256": True, "Info.analyse.started": True })
    
    def getSamplesNotFoundByLocalAV(self):
        return self.__mongodbCollectionRagpicker.find({ "$and": [{ "$or": [{"AntivirusScanAvast.avast" : "OK"}, {"AntivirusScanAvast" : None}]},
                                                                 { "$or": [{"AntivirusScanAvg.Avg" : "OK"}, {"AntivirusScanAvg" : None}]},
                                                                 { "$or": [{"AntivirusScanAvira.Avira.scan" : "OK"}, {"AntivirusScanAvira" : None}]},
                                                                 { "$or": [{"AntivirusScanBitDefender.BitDefender" : "OK"}, {"AntivirusScanBitDefender" : None}]},
                                                                 { "$or": [{"AntivirusScanClamAv.ClamAv" : " OK"}, {"AntivirusScanClamAv" : None}]},
                                                                 { "$or": [{"AntivirusScanCOMODO.COMODO" : "OK"}, {"AntivirusScanCOMODO" : None}]},
                                                                 { "$or": [{"AntivirusScanESET.ESET" : "OK"}, {"AntivirusScanESET" : None}]},
                                                                 { "$or": [{"AntivirusScanFProt.FProt" : "OK"}, {"AntivirusScanFProt" : None}]},
                                                                 { "$or": [{"AntivirusScanF-Secure.F-Secure" : "OK"}, {"AntivirusScanF-Secure" : None}]}
                                                                 ]}, {"Info.file.sha256": True, "Info.analyse.started": True })
        
    def getStatisticsVirusTotal(self):
        ret = {}
        ret["analyzed"] = self.__mongodbCollectionRagpicker.find({"VirusTotal" : {"$ne":None}}).count()
        ret["notAnalyzed"] = self.__mongodbCollectionRagpicker.find({"VirusTotal" : None}).count()
        ret["samplesFound"] = self.__mongodbCollectionRagpicker.find({"VirusTotal.file.positives" : {"$ne":None}}).count()
        ret["SamplesNotFound"] = self.__mongodbCollectionRagpicker.find({"VirusTotal.file.verbose_msg" : {"$ne":None}}).count()        
        return ret
    
    def getStatisticsPackerSignatures(self):
        return self.__mongodbCollectionRagpicker.aggregate([{ '$group' : {'_id' : { 'PublisherO': "$VerifySigs.PublisherO", 'Issuer': "$VerifySigs.Issuer" }, 'count' : { '$sum': 1 }}},{'$sort':{"count": -1}}])
    
    def getStatisticsPackerCompiler(self):
        return self.__mongodbCollectionRagpicker.aggregate([{ '$group' : {'_id' : '$PEID', 'count' : { '$sum': 1 } }}, {'$sort':{'count': -1}}])
    
    def getStatisticsPeCharacteristics(self):
        ret = {}
        ret["exe"] = str(self.__mongodbCollectionRagpicker.find({ "$and": [{"Info.file.EXE" : True}, {"Info.file.DLL" : False}, {"Info.file.DRIVER" : False}]}).count())
        ret["dll"] = str(self.__mongodbCollectionRagpicker.find({ "$and": [{"Info.file.EXE" : False}, {"Info.file.DLL" : True}, {"Info.file.DRIVER" : False}]}).count())
        ret["driver"] = str(self.__mongodbCollectionRagpicker.find({ "$and": [{"Info.file.EXE" : False}, {"Info.file.DLL" : False}, {"Info.file.DRIVER" : True}]}).count())
        ret["noPe"] = str(self.__mongodbCollectionRagpicker.find({ "$and": [{"Info.file.EXE" : None}, {"Info.file.DLL" : None}, {"Info.file.DRIVER" : None}]}).count())
        ret["dllDriver"] = str(self.__mongodbCollectionRagpicker.find({ "$and": [{"Info.file.EXE" : False}, {"Info.file.DLL" : True}, {"Info.file.DRIVER" : True}]}).count())        
        return ret
    
    def getFiletypes(self):
        return self.__mongodbCollectionRagpicker.aggregate([{ '$group' : {'_id' : '$Info.file.type', 'count' : { '$sum': 1 } }}, {'$sort':{'count': -1}}])
    
    def countReportsRagpickerDB(self):
        return self.__mongodbCollectionRagpicker.find().count()
    
    def iterateRagpickerReports(self, sha256):
        for report in self.__mongodbCollectionRagpicker.find({'Info.file.sha256' : sha256}, {"_id" : 0}):
            yield report
    
    # Attention deletes the whole Ragpicker-Database!!!
    # returns number of deleted reports 
    def deleteRagpickerDB(self):
        count = self.__mongodbCollectionRagpicker.find().count()
        # Alle Ragpicker-Daten aus der MongoDB loeschen
        self.__mongodbCollectionRagpicker.remove()
        return count
    
    #Insert Ragpicker-Report in MongoDB
    def insertRagpickerDB(self, report):
        # Store the report
        try:
            self.__mongodbCollectionRagpicker.insert(report)
        except InvalidDocument as e:
            log.exception("Error InvalidDocument: %s", report)
            raise Exception("Error InvalidDocument: {0}".format(e)) 
        except InvalidStringData:
            self.__mongodbCollectionRagpicker.insert(convertDirtyDict2ASCII(report))
          
    #Count Ragpicker-Reports by file (and url)   
    def countRagpickerDB(self, file_md5, url_md5=None):
        if url_md5:
            query = { "$and" : [{ "Info.url.md5": { "$in": [url_md5] } }, { "Info.file.md5": { "$in": [file_md5] } }]}
        else:
            query = { "$and" : [{ "Info.file.md5": { "$in": [file_md5] } }]}
        
        return self.__mongodbCollectionRagpicker.find(query).count()
    
# ------------------------------------------------------------------------------
# Ragpicker SandboxTaskQueue database (MongoDB)
# ------------------------------------------------------------------------------      
    def insertSandboxTaskStatus(self, sandboxName, sha256, taskID, sampleID, taskState=None):
        statusReport = {"sandbox":sandboxName, "sha256":sha256, "sample_id":sampleID, 
                        "task_id":taskID, "task_state":taskState}
        
        # Store the SandboxTaskQueue-Status-report
        self.__mongodbCollectionSandboxTaskQueue.insert(statusReport)
    
    # Attention deletes the whole Ragpicker-SandboxTaskQueue-Database!!!
    # returns number of deleted reports 
    def deleteSandboxTaskQueueDB(self):
        count = self.__mongodbCollectionSandboxTaskQueue.find().count()
        # Alle Daten aus der MongoDB loeschen
        self.__mongodbCollectionSandboxTaskQueue.remove()
        return count
    
# ------------------------------------------------------------------------------
# Ragpicker families database (MongoDB)
# ------------------------------------------------------------------------------    
    def insertFamily(self, familyReport):
        # Store the family-report
        self.__mongodbCollectionFamilies.insert(familyReport)
        
    #Count Ragpicker-Reports by file (and url)   
    def countFamilyDB(self, parentObjectSHA256):
        query = { "$and" : [{ "parentObjectSHA256": { "$in": [parentObjectSHA256] } }]}
        return self.__mongodbCollectionFamilies.find(query).count()        
        
    def iterateFamilyReports(self, sha256):
        for report in self.__mongodbCollectionFamilies.find({'parentObjectSHA256' : sha256}, {"_id" : 0}):
            yield report        
        
    # Attention deletes the whole Ragpicker-Family-Database!!!
    # returns number of deleted reports 
    def deleteFamilyDB(self):
        count = self.__mongodbCollectionFamilies.find().count()
        # Alle Ragpicker-Daten aus der MongoDB loeschen
        self.__mongodbCollectionFamilies.remove()
        return count
        
# ------------------------------------------------------------------------------
# CodeDB Database (MongoDB)
# ------------------------------------------------------------------------------

    def isCodeDBEnabled(self):
        return self.__codedbEnabled

    def countReportsCodeDB(self):
        return self.__codedbCollectionCodedb.find().count()

    # Attention deletes the whole CodeDB-Database!!!
    # returns number of deleted reports 
    def deleteCodeDB(self):
        count = self.__codedbCollectionCodedb.find().count()
        # Alle CodeDB-Reports aus der MongoDB loeschen
        self.__codedbCollectionCodedb.remove()
        return count
    
    #Count CodeDB-Reports by file sha256
    def countCodeDB(self, file_sha256):
        return self.__codedbCollectionCodedb.find({ "sha256" : file_sha256}).count()
    
    #Insert CodeDB-Report in MongoDB
    def insertCodeDB(self, report):
        # Store the report
        try:
            self.__codedbCollectionCodedb.insert(report)
        except InvalidStringData:
            self.__codedbCollectionCodedb.insert(convertDirtyDict2ASCII(report))         