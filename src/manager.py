#!/usr/bin/python
#                              _        _                
#   _ __   __ _   __ _  _ __  (_)  ___ | | __  ___  _ __ 
#  | '__| / _` | / _` || '_ \ | | / __|| |/ / / _ \| '__|
#  | |   | (_| || (_| || |_) || || (__ |   < |  __/| |   
#  |_|    \__,_| \__, || .__/ |_| \___||_|\_\ \___||_|   
#                |___/ |_|                               
#
# Plugin based malware crawler. 
# Use this tool if you are testing antivirus products, collecting malware 
# for another analyzer/zoo.
# Many thanks to the cuckoo-sandbox team for the Architectural design ideas.
# Includes code from cuckoo-sandbox (c) 2013 http://www.cuckoosandbox.org 
# and mwcrawler, (c) 2012 Ricardo Dias
#
# http://code.google.com/p/malware-crawler/
#
# Robby Zeitfuchs - robby@zeitfuchs.org - 2013-2015
# Mark Lawrenz - Mark.Lawrenz@web.de
#
# any subjection, tips, improvement are welcome
#
# Licence: GNU GPL v.3.0
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.

import os
import sys
import json
import base64
import httplib2
import logging
import codecs
import shutil
import datetime
import tempfile
import jsonpickle
import zipfile
import argparse
import utils.magic as magic
import uuid

from urllib import urlencode
from zipfile import ZipFile
from core.config import Config
from core.database import Database
from core.vxCageHandler import VxCageHandler
from core.constants import RAGPICKER_ROOT
from core.commonutils import DatetimeHandler
from core.commonutils import UUIDHandler
from core.commonutils import convertDirtyDict2ASCII

log = logging.getLogger("Manager")

# Config-Parameter
cfgReporting = Config(os.path.join(RAGPICKER_ROOT, 'config', 'reporting.conf'))

# Eigene neue Tags zu Sample hinzufuegen. 
# Typedef: POST /sample/tags/update (sha256,tags(string)) -> json(Status=status_string)
CODE_DB_URL_TAG = "https://%s:%s/sample/tags/update"

# Import Ragpicker-Data in VxCage and MongoDB
def ragpickerImport(zipFile, database, vxcage):
    log.info(zipFile)
    try:
        # crate temp-dir
        tmpPath = getTmpPath("export_")
        tmpPath = os.path.normpath(tmpPath) + os.sep
        # unpack archive
        zip = ZipFile(zipFile)
        zip.extractall(path=tmpPath)
        
        #Iterate files
        for file in os.listdir(tmpPath):
            if file.endswith("ragpicker.json"):
                # Import reports in MongoDB
                f = open(os.path.join(tmpPath, file))
                report = jsonpickle.decode(f.read())
                    
                # Count query using URL hash and file hash
                count = database.countRagpickerDB(report["Info"]["file"]["md5"], report["Info"]["url"]["md5"])
                
                # If report available for the file and url -> not insert
                if count == 0:
                    database.insertRagpickerDB(report)
                    log.info("Import Ragpicker-Report: " + file)
            elif file.endswith("family.json"):
                # Import reports in MongoDB
                f = open(os.path.join(tmpPath, file))
                report = jsonpickle.decode(f.read())

                # Count query using URL hash and file hash
                count = database.countFamilyDB(report["parentObjectSHA256"])                
                
                # If family report available for the file -> not insert
                if count == 0:
                    database.insertFamily(report)
                    log.info("Import Family-Report: " + file)                
            else:
                # Import malware-file in VxCage
                if vxcage.isFileInCage(sha256 = file) == False:
                    vxcage.upload(os.path.join(tmpPath, file), file, "ragpicker, import")
                    log.info("Import VxCage:  " + file)
    except Exception as msg:
        log.exception(msg)
    finally:
        # finally delete temp-dir
        shutil.rmtree(tmpPath, ignore_errors=True)

# Function for export Ragpicker-Data from VxCage and MongoDB to zip-file
def rapickerExport(sha256, dumpDir, database, vxCage):    
    #check sh256
    if (len(sha256.rstrip()) != 64):
        raise Exception("%s is not a sha256!" % sha256) 
           
    try:
        log.info("Export Data for: %s" % sha256)
        
        # dumpDir format
        dumpDir = os.path.normpath(dumpDir) + os.sep
    
        # crate temp-dir
        tmpPath = getTmpPath("export_")
        tmpPath = os.path.normpath(tmpPath) + os.sep
        
        # export file from vxcage -> temp-dir
        vxCage.exportVxCage(sha256, tmpPath)
        
        # export json-reports from mongodb -> temp dir
        for report in database.iterateRagpickerReports(sha256):
            writeRagpickerJsonReport(sha256, tmpPath, report)

        for report in database.iterateFamilyReports(sha256):
            writeFamilyJsonReport(sha256, tmpPath, report)        
        
        # goto tempDir
        os.chdir(tmpPath)
        
        # zip file and report -> dump-dir -> zipfilename = sha256 + .ragpicker
        createExportZip(sha256, dumpDir, tmpPath) 
    finally:
        #goto dumpDir
        os.chdir(dumpDir)
        # finally delete temp-dir
        shutil.rmtree(tmpPath, ignore_errors=True)

# Sort malware files by file type
def sortFiles(source, destination):
    if not os.path.exists(source):
        raise Exception('Enter a valid source directory')
    if not os.path.exists(destination):
        raise Exception('Enter a valid destination directory')
            
    for root, dirs, files in os.walk(source, topdown=False):
        for file in files:
            extension = getFileType(os.path.join(source, file))
            destinationPath = os.path.join(destination, extension)
              
            if not os.path.exists(destinationPath):
                log.info("mkdir %s" % destinationPath)
                os.mkdir(destinationPath)
            if os.path.exists(os.path.join(destinationPath, file)):
                log.warning('File exists:' + os.path.join(root, file))
            else:
                log.info("copy %s -> %s" % (os.path.join(root, file), destinationPath))
                shutil.copy2(os.path.join(root, file), destinationPath)

# Create Temp-Folden and return the Path
def getTmpPath(prefix):
    tmppath = tempfile.gettempdir()
    targetpath = os.path.join(tmppath, "ragpicker-tmp")
    if not os.path.exists(targetpath):
        os.mkdir(targetpath)
        
    tempPath = tempfile.mkdtemp(prefix=prefix, dir=targetpath)    
    return tempPath   

# Get short MIME file type
def getFileType(file):
    try:
        file_type = magic.from_file(file)
    except:
        try:
            import subprocess
            file_process = subprocess.Popen(['file', '-b', file],
                                            stdout=subprocess.PIPE)
            file_type = file_process.stdout.read().strip()
        except:
            return None

    file_type = file_type.split(' ')[0]
    file_type = file_type.replace("/", "_")
    return file_type
    
# Write Report to Temp-Folder 
def writeJsonReportFile(exportDir, dbresults, fileName):
    try:
        jsonpickle.set_encoder_options('simplejson', indent=4)
        jsonpickle.handlers.registry.register(datetime.datetime, DatetimeHandler)
        jsonpickle.handlers.registry.register(uuid.UUID, UUIDHandler)
        jsonReport = jsonpickle.encode(dbresults)
    except (UnicodeError, TypeError):
        jsonReport = jsonpickle.encode(convertDirtyDict2ASCII(dbresults))
    try:
        if not os.path.exists(exportDir + fileName):
            report = codecs.open(os.path.join(exportDir, fileName), "w", "utf-8")
            report.write(jsonReport)
            report.close()
    except (TypeError, IOError) as e:
        raise Exception("Failed to generate JSON report: %s" % e)

def writeFamilyJsonReport(sha256, exportDir, dbresults):
    # report-name file-sha256 and source-md5
    fileName = "%s_family.json" % sha256
    writeJsonReportFile(exportDir, dbresults, fileName)      
    
def writeRagpickerJsonReport(sha256, exportDir, dbresults):
    # Source MD5
    sourceMD5 = dbresults.get("Info").get("url").get("md5")
    # report-name file-sha256 and source-md5
    fileName = "%s_%s_ragpicker.json" % (sha256, sourceMD5)
    writeJsonReportFile(exportDir, dbresults, fileName) 
    
# Create ZIP-File with file and ragpicker-reports from temp-dir
def createExportZip(sha256, exportDir, tempDir):  
    zipFileName = "export_%s.ragpicker" % sha256
    
    # check file exist 
    if os.path.isfile(os.path.join(exportDir, zipFileName)):
        raise Exception("File %s already exists." % os.path.join(exportDir, zipFileName))  
    
    # creating archive 
    zf = zipfile.ZipFile(os.path.join(exportDir, zipFileName), mode='w')
    
    # Zip iles in tempdir
    try:
        for f in os.listdir(tempDir):
            zf.write(f)
    finally:
        zf.close()

# Iterate over a sha256 text file
def iterateSha256File(fileName, isJson):
    file = open(fileName,"r")

    if isJson:
        data = json.load(file)
        for sha256 in data.itervalues():
            yield sha256.rstrip()
    else:
        for sha256 in file:
            yield sha256.rstrip()
    
    file.close()

def submitTag(sha256, tags, config):
    headers = {"Authorization" : "Basic %s" % base64.encodestring("%s:%s" % (config.get("user"), 
                                                                             config.get("password"))).replace('\n', '')}
    data = dict(sha256=sha256, tags=tags)
    h = httplib2.Http(".cache", disable_ssl_certificate_validation=True)    
    response, content = h.request(CODE_DB_URL_TAG % (config.get("host"), 
                                                     config.get("port")), "POST", body=urlencode(data), headers=headers)      
    
    if not "'status': '200'" in str(response) :
        log.error("%s --> %s = %s" % (sha256, tags, str(content))) 
        
    data = json.loads(content)
    log.info("%s --> %s = %s" % (sha256, tags, data.get("Status")))

if __name__ == '__main__':    
    # Datenbank
    database = Database()
    # VxCage-Handler
    vxCage = VxCageHandler()
    vxcageEnabled = cfgReporting.getOption("vxcage", "enabled")        
        
    parser = argparse.ArgumentParser(description='Ragpicker Manager')
    subparsers = parser.add_subparsers(title='subcommands', description='valid subcommands', help='additional help')
    parser_stop = subparsers.add_parser('stop', help='Stops a running Ragpicker instance')
    parser_stop.set_defaults(which='stop')
    parser_export = subparsers.add_parser('export', help='Export Ragpicker-Data')
    parser_export.set_defaults(which='export')
    parser_export.add_argument('-d','--dirname', required=True, help='Export-Directory')
    parser_export.add_argument('-f','--sha256_file', required=True, help='SHA256-File')
    parser_export.add_argument('--json', default=False, help='File in json-format? Default=False')
    parser_vxcage = subparsers.add_parser('vxcage', help='Exports only the malware files from the VxCage')
    parser_vxcage.set_defaults(which='vxcage')
    parser_vxcage.add_argument('-d','--dirname', required=True, help='Export-Directory')
    parser_vxcage.add_argument('-f','--sha256_file', required=True, help='SHA256-File')
    parser_vxcage.add_argument('--json', default=False, help='File in json-format? Default=False')
    parser_import = subparsers.add_parser('import', help='Import Ragpicker-Data')
    parser_import.set_defaults(which='import')
    parser_import.add_argument('dirname', help='Directory with Ragpicker-data')
    
    parser_sort = subparsers.add_parser('sort', help='Sort malware files by file type')
    parser_sort.set_defaults(which='sort')
    parser_sort.add_argument('-s','--source_dir', required=True, help='Source-Directory')
    parser_sort.add_argument('-d','--destination_dir', required=True, help='Destination-Directory')
    
    parser_codeDBTag = subparsers.add_parser('codeDBTag', help='Export Ragpicker-Data')
    parser_codeDBTag.set_defaults(which='codeDBTag')
    parser_codeDBTag.add_argument('-t','--tag', required=True, help='CodeDB-Tag Format: \"key1 : value1 ; key2 : value2 ;\" Beispiel \"Quelle: hausintern; Zeus: Version x.y ;\"')
    parser_codeDBTag.add_argument('-f','--sha256_file', required=True, help='SHA256-File')
    parser_codeDBTag.add_argument('--json', default=False, help='File in json-format? Default=False')

    args = vars(parser.parse_args())
    
    # config logger
    log_conf = dict(level=logging.INFO,
        format='%(levelname)s %(name)s %(module)s:%(lineno)d %(message)s')
    logging.basicConfig(**log_conf)
    
    # check mongodb and vxcage enebled
    if not database.isRagpickerDBEnabled():
        log.error("Sorry: MongoDB for Ragpicker is not enabled!")
        sys.exit()
    if not vxcageEnabled:
        log.error("Sorry: VxCage for Ragpicker is not enabled!")
        sys.exit()  
        
    if args['which'] == 'vxcage':
        log.info("Exporting VxCage {} {}".format(args['dirname'], args['sha256_file']))
        dumpDir = os.path.normpath(args['dirname']) + os.sep
        
        for sha256 in iterateSha256File(args['sha256_file'], args['json']):
            try:
                vxCage.exportVxCage(sha256, dumpDir)  
            except (Exception) as e:
                log.error("Export-Error: %s" % e)        
    elif args['which'] == 'export':
        log.info("Exporting {} {}".format(args['dirname'], args['sha256_file']))
        dumpDir = os.path.normpath(args['dirname']) + os.sep
        
        for sha256 in iterateSha256File(args['sha256_file'], args['json']):
            try:
                rapickerExport(sha256, dumpDir, database, vxCage)      
            except (Exception) as e:
                log.error("Export-Error: %s" % e)
    elif args['which'] == 'codeDBTag':
        log.info("codeDBTag {} {}".format(args['tag'], args['sha256_file']))
        config = cfgReporting.get("codeDB")

        if not config.get("enabled"):
            log.error("Sorry: CodeDB for Ragpicker is not enabled!")
            sys.exit()  
        
        for sha256 in iterateSha256File(args['sha256_file'], args['json']):
            try:
                submitTag(sha256, args['tag'], config)      
            except (Exception) as e:
                log.error("CodeDBTag-Error: %s" % e)
    elif args['which'] == 'import':
        log.info("Importing {}".format(args['dirname']))
        impDir = os.path.normpath(args['dirname']) + os.sep
        
        for file in os.listdir(impDir):
            if file.endswith(".ragpicker"):
                try:
                    ragpickerImport(os.path.join(impDir, file), database, vxCage)
                except (Exception) as e:
                    log.error("Import-Error: %s" % e)
    elif args['which'] == 'sort':
        log.info("Sorting {} {}".format(args['source_dir'], args['destination_dir']))
        source = os.path.normpath(args['source_dir']) + os.sep
        dest = os.path.normpath(args['destination_dir']) + os.sep
        sortFiles(source, dest)
    elif args['which'] == 'stop':
        log.info("Stop Ragpicker")
        os.system("killall -r .*ragpicker.*")

    sys.exit()