# Copyright (C) 2013-2015 Ragpicker Developers.
# This file is part of Ragpicker Malware Crawler - http://code.google.com/p/malware-crawler/

from yapsy.IPlugin import IPlugin

from core.abstracts import Report

class MySQL(IPlugin, Report):
    """Stores data from long-run analysis in MySQL."""

    def run(self, results, objfile):
        # Import muss hier stehen, sonst kommt es bei Konfiguration ohne Mysql zum Fehler
        from core.databaseMysql import DatabaseMySQL
        """Writes report.
        @param results: analysis results dictionary.
        @param objfile: file object
        """
        database = DatabaseMySQL()
        
        print "mysql.py Methode Run"
        """
        # Count query using URL hash and file hash
        count = database.countRagpickerDB(results["Info"]["file"]["md5"], results["Info"]["url"]["md5"])
        
        # If report available for the file and url -> not insert
        if count == 0:
            # Create a copy of the dictionary. This is done in order to not modify
            # the original dictionary and possibly compromise the following
            # reporting modules.
            report = dict(results)
            # Store the report
            database.insertRagpickerDB(report)
        """
    def deleteAll(self):  
        """Deletes all reports.
        """ 
        print "mysql.py Methode DeleteAll"
        """ 
        # Alle Ragpicker-Daten aus der MongoDB loeschen
        count = Database().deleteRagpickerDB()
        
        print "*** MongoDB (Ragpicker)***"
        print "deleted documents:" + str(count)
        print ""
        """