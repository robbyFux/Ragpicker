# Copyright (C) 2013-2015 Ragpicker Developers.
# This file is part of Ragpicker Malware Crawler - http://code.google.com/p/malware-crawler/

import logging

from yapsy.IPlugin import IPlugin
from core.database import Database
from core.abstracts import Report

log = logging.getLogger("MongoDB")

class MongoDB(IPlugin, Report):
    """Stores report in MongoDB."""

    def run(self, results, objfile):
        """Writes report.
        @param results: analysis results dictionary.
        @param objfile: file object
        """
        database = Database()

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

        count = database.countFamilyDB(objfile.family.parentObjectSHA256)
        if count == 0:    
            if objfile.family.unpackedObjectSHA256 != "" or len(objfile.family.siblingObjectsSHA256) > 0:
                log.info(objfile.family)
                report = dict(objfile.family.__dict__)
                database.insertFamily(report)
        
    def deleteAll(self):  
        """Deletes all reports.
        """  
        # Alle Ragpicker-Daten aus der MongoDB loeschen
        count = Database().deleteRagpickerDB()
        
        print "*** MongoDB (Ragpicker)***"
        print "deleted documents:" + str(count)
        print ""

        count = Database().deleteFamilyDB()
        
        print "*** MongoDB (Family)***"
        print "deleted documents:" + str(count)
        print ""
        
        count = Database().deleteSandboxTaskQueueDB()
        
        print "*** MongoDB (SandboxTaskQueue)***"
        print "deleted documents:" + str(count)
        print ""
