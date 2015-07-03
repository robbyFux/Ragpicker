# Copyright (C) 2013-2015 Ragpicker Developers.
# This file is part of Ragpicker Malware Crawler - http://code.google.com/p/malware-crawler/

import os
import logging
from core.config import Config
from core.constants import RAGPICKER_ROOT

try:
    import MySQLdb
except ImportError:
    raise Exception("MySQLdb is required for working with MySQL: http://mysql-python.sourceforge.net/") 

def singleton(class_):
    instances = {}
    def getinstance(*args, **kwargs):
        if class_ not in instances:
            instances[class_] = class_(*args, **kwargs)
        return instances[class_]
    return getinstance
  
log = logging.getLogger("DatabaseMySQL")  
  
@singleton
class DatabaseMySQL():
    
    def __init__(self):
        self.__cfgReporting = Config(os.path.join(RAGPICKER_ROOT, 'config', 'reporting.conf'))
        self.__mysqlEnabled = self.__cfgReporting.getOption("mysql", "enabled")
        
        if self.__mysqlEnabled:
            #Anbindung an Datenbank MySQL herstellen
            try:
                mysqlHost = self.__cfgReporting.getOption("mysql", "host")
                mysqlPort = self.__cfgReporting.getOption("mysql", "port")
                mysqlDatabase = self.__cfgReporting.getOption("mysql", "database")
                mysqlUser = self.__cfgReporting.getOption("mysql", "user")
                mysqlPassword = self.__cfgReporting.getOption("mysql", "password")
                self.__mysqlConnection = MySQLdb.Connect(host=mysqlHost, port=mysqlPort, db=mysqlDatabase, user=mysqlUser, passwd=mysqlPassword)
            except (Exception) as e:
                raise Exception("Cannot connect to MySQL (ragpicker): %s" % e)   
            
    def __del__(self):
        if self.__mysqlEnabled:
            self.__mysqlConnection.close()
            
# ------------------------------------------------------------------------------
# Ragpicker Database (MySQL)
# ------------------------------------------------------------------------------    

    def isRagpickerDBEnabledMySQL(self):
        return self.__mysqlEnabled   
