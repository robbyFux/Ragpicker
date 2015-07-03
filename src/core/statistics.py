# Copyright (C) 2013-2015 Ragpicker Developers.
# This file is part of Ragpicker Malware Crawler - http://code.google.com/p/malware-crawler/

import os
import sys
from core.config import Config
from core.database import Database
from core.constants import RAGPICKER_ROOT

try:
    from prettytable import PrettyTable
except ImportError:
    raise Exception("PrettyTable is required for using statistics: https://code.google.com/p/prettytable/")

class Statistics():
    
    def __init__(self):
        # Datenbank
        self.__database = Database()
        # Kofiguration aus der reporting.conf holen
        self.__cfgReporting = Config(os.path.join(RAGPICKER_ROOT, 'config', 'reporting.conf'))
        self.__vxcageEnabled = self.__cfgReporting.getOption("vxcage", "enabled")
        self.__vxcageHost = self.__cfgReporting.getOption("vxcage", "host")
        self.__vxcagePort = self.__cfgReporting.getOption("vxcage", "port")
               
    def runStatisticsLong(self):
        #Pruefen ob VxCage und MongoDB aktiviert sind
        if self.__database.isRagpickerDBEnabled():
            if self.__vxcageEnabled:
                self.__runStatisticsMongodbLong()
                
                if self.__database.isCodeDBEnabled():
                    self.__runStatisticsCodedb()
            else:
                print("vxcage in reporting.conf is not enabled")
                sys.stdout.flush()
        else:
            print("mongodb in reporting.conf is not enabled")
            sys.stdout.flush()
            
    def runStatisticsShort(self):
        #Pruefen ob VxCage und MongoDB aktiviert sind
        if self.__database.isRagpickerDBEnabled():
            if self.__vxcageEnabled:
                self.__runStatisticsMongodbShort()
                
                if self.__database.isCodeDBEnabled():
                    self.__runStatisticsCodedb()
            else:
                print("vxcage in reporting.conf is not enabled")
                sys.stdout.flush()
        else:
            print("mongodb in reporting.conf is not enabled")
            sys.stdout.flush()
            
    def runStatisticsAV(self):
        #Pruefen ob VxCage und MongoDB aktiviert sind
        if self.__database.isRagpickerDBEnabled():
            if self.__vxcageEnabled:
                self.__runStatisticsAV()
                
            else:
                print("vxcage in reporting.conf is not enabled")
                sys.stdout.flush()
        else:
            print("mongodb in reporting.conf is not enabled")
            sys.stdout.flush()        

    def __runStatisticsMongodbLong(self):
        print "**************************************"
        print "*** Statistics MongoDB (Ragpicker) ***"
        print "**************************************"
        print ""
        
        print "Number of malware samples in database:", self.__database.countReportsRagpickerDB()
        print ""
        
        #Statistiken der eingesetzten AV-Produkte 
        self.__runStatisticsAVProducts()
        
        #Liste der letzen 20 Samples, die weder auf VT noch von einem lokalen AV gefunden wurden
        self.__runStatisticsLast20SamplesNotFoundByAV()
        
        #Liste der letzen 20 Samples, die nicht auf VT gefunden wurden
        self.__runStatisticsLast20SamplesNotFoundByVT()
        
        #Liste der letzen 20 Samples, die nicht von einem lokalen AV-Produkt gefunden wurden
        self.__runStatisticsLast20SamplesNotFoundByLocalAV()
        
        #Liste und Haeufigkeit der Filetypes
        self.__runStatisticsFiletypes()
        
        #Haeufigkeit der PE Charakteristiken
        self.__runStatisticsPeCharacteristics()
        
        #Liste und Haeufigkeit der verwendeten Packer/Compiler in der Malware
        self.__runStatisticsPackerCompiler()
        
        #Liste der verwendeten digitalen Signaturen     
        self.__runStatisticsPackerSignatures()
        
        sys.stdout.flush()
        
    def __runStatisticsMongodbShort(self):  
        print "**************************************"
        print "*** Statistics MongoDB (Ragpicker) ***"
        print "**************************************"
        print ""
        
        print "Number of malware samples in database:", self.__database.countReportsRagpickerDB()
        print ""  
        
        #Liste und Haeufigkeit der Filetypes
        self.__runStatisticsFiletypes()
        
        #Haeufigkeit der PE Charakteristiken
        self.__runStatisticsPeCharacteristics()
                
        sys.stdout.flush()
        
    def __runStatisticsAV(self):  
        print "**************************************"
        print "*** Statistics MongoDB (Ragpicker) ***"
        print "**************************************"
        print ""
        
        print "Number of malware samples in database:", self.__database.countReportsRagpickerDB()
        print ""  
        
        #Statistiken der eingesetzten AV-Produkte 
        self.__runStatisticsAVProducts()
        
        #Liste der letzen 20 Samples, die weder auf VT noch von einem lokalen AV gefunden wurden
        self.__runStatisticsLast20SamplesNotFoundByAV()
        
        #Liste der letzen 20 Samples, die nicht auf VT gefunden wurden
        self.__runStatisticsLast20SamplesNotFoundByVT()
        
        #Liste der letzen 20 Samples, die nicht von einem lokalen AV-Produkt gefunden wurden
        self.__runStatisticsLast20SamplesNotFoundByLocalAV()
        
        sys.stdout.flush()  
        
    def __runStatisticsCodedb(self):
        print "***********************************"
        print "*** Statistics MongoDB (CodeDB) ***"
        print "***********************************"
        print ""
        print "Number of malware samples in database:", self.__database.countReportsCodeDB()
        
        print ""
        sys.stdout.flush()
        
        
    def __runStatisticsFiletypes(self):   
        #Liste und Haeufigkeit der Filetypes
        print "Filetypes of malware"
        res = self.__database.getFiletypes()
        
        table = PrettyTable(["filetype", "count"])
        table.align["filetype"] = "l"
        table.align["count"] = "c"
        table.padding_width = 1
                
        try:
            for values in res['result']:
                
                if values.get("_id"):
                    outputPacker = values.get("_id")
                    outputCount = str(values.get("count"))
                    table.add_row([outputPacker, outputCount])
            
            print(table)
                    
        except KeyError:
            raise Exception("Dict has no key 'result' ")  
       
        print ""

    def __runStatisticsPeCharacteristics(self):   
        #Haeufigkeit der PE Charakteristiken
        print "PE-Characteristics of malware"
        peC = self.__database.getStatisticsPeCharacteristics()
        
        table = PrettyTable(["pe-characteristics", "count"])
        table.align["pe-characteristics"] = "l"
        table.align["count"] = "c"
        table.padding_width = 1
        table.add_row(["EXE", peC.get("exe")])        
        table.add_row(["DLL", peC.get("dll")])
        table.add_row(["Driver", peC.get("driver")])
        table.add_row(["DLL/Driver", peC.get("dllDriver")])
        table.add_row(["No PE File", peC.get("noPe")])
          
        print (table)
        print ""

    def __runStatisticsPackerCompiler(self): 
        #Liste und Haeufigkeit der verwendeten Packer/Compiler in der Malware
        print "Packer/compiler used in malware"
        res = self.__database.getStatisticsPackerCompiler()
        
        table = PrettyTable(["packer/compiler", "count"])
        table.align["packer/compiler"] = "l"
        table.align["count"] = "c"
        table.padding_width = 1
        
        try:
            for values in res['result']:
                
                if values.get("_id"):
                    outputPacker = values.get("_id")[0]
                    outputCount = str(values.get("count"))
                    table.add_row([outputPacker, outputCount])
            
            print(table)
                    
        except KeyError:
            raise Exception("Dict has no key 'result' ")    
        
        print " "
        
    def __runStatisticsPackerSignatures(self): 
        #Liste der verwendeten digitalen Signaturen    
        print "Signatures used by malware"
        res = self.__database.getStatisticsPackerSignatures()
        
        table = PrettyTable(["publisher", "issuer", "count"])
        table.align["publisher"] = "l"
        table.align["issuer"] = "l"
        table.align["count"] = "c"
        table.padding_width = 1
        
        try:
            for values in res['result']:
                
                if values.get("_id"):
                    
                    outputPublisher = values.get("_id").get("PublisherO")
                    
                    if values.get("_id").get("Issuer"):
                        outputIssuer = values.get("_id").get("Issuer")
                    else:
                        outputIssuer = " "
                    
                    outputCount = str(values.get("count"))
            
                    table.add_row([outputPublisher, outputIssuer, outputCount])
                            
            print(table)
   
        except KeyError:
            raise Exception("Dict has no key 'result' ")    
        
        print ""
   
    def __runStatisticsLast20SamplesNotFoundByAV(self):
        #Liste der letzen 20 Samples, die weder auf VT noch von einem lokalen AV gefunden wurden
        print "Last 20 samples not found by VirusTotal and local AV-Products"
        res = sorted(self.__database.getSamplesNotFoundByAV(), reverse=True)
        
        table = PrettyTable(["timestamp of crawling", "sha256"])
        table.align["timestamp of crawling"] = "c"
        table.align["sha256"] = "c"
        table.padding_width = 1
        
        try:
            for values in res:
                
                sha256 = values.get("Info").get("file").get("sha256")
                timestamp = values.get("Info").get("analyse").get("started")
                table.add_row([timestamp, sha256])
            
            print(table.get_string(start=0, end=20))       
        except KeyError:
            raise Exception("Dict has no key 'Info' ")  
         
        print ""
        
    def __runStatisticsLast20SamplesNotFoundByVT(self):
        #Liste der letzen 20 Samples, die nicht auf VirusTotal gefunden wurden
        print "Last 20 samples not found by VirusTotal"
        res = sorted(self.__database.getSamplesNotFoundByVT(), reverse=True)
        
        table = PrettyTable(["timestamp of crawling", "sha256"])
        table.align["timestamp of crawling"] = "c"
        table.align["sha256"] = "c"
        table.padding_width = 1
        
        try:
            for values in res:
                
                sha256 = values.get("Info").get("file").get("sha256")
                timestamp = values.get("Info").get("analyse").get("started")
                table.add_row([timestamp, sha256])
            
            print(table.get_string(start=0, end=20))       
        except KeyError:
            raise Exception("Dict has no key 'Info' ")  
         
        print ""
    
    def __runStatisticsLast20SamplesNotFoundByLocalAV(self):
        #Liste der letzen 20 Samples, die nicht von einem lokalen AV-Produkt gefunden wurden
        print "Last 20 samples not found by local AV-Products"
        res = sorted(self.__database.getSamplesNotFoundByLocalAV(), reverse=True)
        
        table = PrettyTable(["timestamp of crawling", "sha256"])
        table.align["timestamp of crawling"] = "c"
        table.align["sha256"] = "c"
        table.padding_width = 1
        
        try:
            for values in res:
                
                sha256 = values.get("Info").get("file").get("sha256")
                timestamp = values.get("Info").get("analyse").get("started")
                table.add_row([timestamp, sha256])
            
            print(table.get_string(start=0, end=20))       
        except KeyError:
            raise Exception("Dict has no key 'Info' ")  
         
        print ""
        
    def __runStatisticsAVProducts(self): 
        #Statistiken der eingesetzten AV-Produkte 
        
        #VirusTotal und lokale AV-Produkte
        print "VirusTotal and local AV-Products"
        print "   Samples rated as none-malware by all AV-Products at time of crawling:", \
                                            self.__database.getStatisticsNoneMalwareByAV()
        print ""
        
        #VirusTotal
        ret = self.__database.getStatisticsVirusTotal()
        print "VirusTotal"
        print "   Samples analyzed at time of crawling:", ret.get("analyzed")
        print "   Samples not analyzed at time of crawling:", ret.get("notAnalyzed")
        print "   Samples found at time of crawling:", ret.get("samplesFound")
        print "   Samples not found at time of crawling:", ret.get("SamplesNotFound")
        print ""
        
        #Lokale AV-Produkte
        print "Local AV-Products"
        print "   analyzed     => Samples analyzed at time of crawling"
        print "   not analyzed => Samples not analyzed at time of crawling"
        print "   malware      => Samples rated as malware at time of crawling"
        print "   none-malware => Samples rated as none-malware at time of crawling"
                
        table = PrettyTable(["product", "analyzed", "not analyzed", "malware", "none-malware", "detection rate"])
        table.align["product"] = "l"
        table.align["analyzed"] = "r"
        table.align["not analyzed"] = "r"
        table.align["malware"] = "r"
        table.align["none-malware"] = "r"
        table.align["detection rate"] = "r"
        table.padding_width = 1
        
        # Statistik Daten holen
        ret = self.__database.getStatisticsAntivirus()
        # Table-Body zusammenbauen
        for av in ret:
            table.add_row([av.get("product"), av.get("analyzed"), av.get("notanalyzed"), av.get("malware"), av.get("nonemalware"), av.get("rate")])
        
        print(table)
        print ""