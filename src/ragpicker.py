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

from multiprocessing import Pool
from os import walk
from os.path import join
import argparse
import hashlib
import json
import logging
import os
import sys
import time
import urllib2

from core.config import Config
from core.constants import RAGPICKER_BUILD_DATE
from core.constants import RAGPICKER_ROOT
from core.constants import RAGPICKER_VERSION
from core.worker import Worker
from utils.logo import logo 


try:
	from yapsy.PluginManager import PluginManager
except ImportError:
	raise ImportError, 'Yapsy (Yet Another Plugin System) is required to run this program : http://yapsy.sourceforge.net'

BLACK, RED, GREEN, YELLOW, BLUE, MAGENTA, CYAN, WHITE = range(8)
VERSION_URL = "https://raw.githubusercontent.com/robbyFux/Ragpicker/master/versions/ragpicker_version.json"

log = logging.getLogger("Main")

def main():
	mapURL = {}
	
	logo()
	parser = argparse.ArgumentParser(description='Ragpicker Malware Crawler')
	parser.add_argument("-a", "--artwork", help="Show artwork", action="store_true", required=False)
	parser.add_argument("-p", "--processes", type=int, default=3, help="Number of processes (default=3, max=6)")
	parser.add_argument("-u", "--url", help="Download and analysis from a single URL")
	parser.add_argument("-d", "--directory", help="Load files from local directory")
	parser.add_argument("-i", "--info", help="Print Ragpicker config infos", action="store_true", required=False)
	parser.add_argument("-da", "--delete", help="Delete all stored data", action="store_true")
	parser.add_argument('--log-level', default=logging.INFO, help='logging level, default=logging.INFO')
	parser.add_argument('--log-filename', help='logging filename')
	parser.add_argument('--version', action='version', version='Ragpicker version ' + RAGPICKER_VERSION)

	global args 
	args = parser.parse_args()
	
	if args.artwork:
		try:
			while True:
				time.sleep(1)
				logo()
		except KeyboardInterrupt:
			return
		
	if args.log_level:
		log_conf = dict(level=args.log_level,
			format='%(levelname)s %(name)s %(module)s:%(lineno)d %(message)s')

		if args.log_filename:
			log_conf['filename'] = args.log_filename
			log.info("log-filename: " + args.log_filename)

		logging.basicConfig(**log_conf)
	
	if args.delete:
		worker = Worker()
		worker.runDelete()
		return
	
	if args.info:
		printRagpickerInfos(True)
		return
	
	if args.url:
		log.info(color("Download and analysis from %s" % args.url, RED))
		runWorker(args.url)
	elif args.directory:
		printRagpickerInfos()
		log.info(color("Load files from local directory %s" % args.directory, RED))
		mapURL = getLocalFiles(args.directory)
	else:			
		printRagpickerInfos()
		# Malware URLs Crawlen 
		mapURL = runCrawler()
		
	# Max Threads=6
	if args.processes > 6:
		args.processes = 6
		
	log.info(color("Processes: " + str(args.processes), RED))	
	log.info(color("Process " + str(len(mapURL)) + " URLs", RED))
	
	# Create Process Pool
	pool = Pool(processes=args.processes)
	
	# Malware Download, process and reporting
	for url in mapURL.values():
		pool.apply_async(runWorker, args=(url,))
		
	pool.close()
	pool.join()
		
def getLocalFiles(directory):
	mapURL = {}
	
	# give the queue some data
	for root, dirs, files in walk(directory):
		for file in files:
			# do concatenation here to get full path 
			full_path = join(root, file)
			md5 = hashlib.md5(full_path).hexdigest()
			mapURL[md5] = "file://" + full_path
			
	return mapURL
			
def runCrawler():
	mapURL = {}
	cfgCrawler = Config(os.path.join(RAGPICKER_ROOT, 'config', 'crawler.conf'))	
	
	# Build the PluginManager
	crawlerPluginManager = PluginManager()
	crawlerPluginManager.setPluginPlaces(["crawler"])
	crawlerPluginManager.collectPlugins()
	
	# Trigger run from the "Crawler" plugins
	for pluginInfo in sorted(crawlerPluginManager.getAllPlugins(), key=lambda PluginInfo: PluginInfo.name):
		crawlerModul = pluginInfo.plugin_object
		
		# Config for crawler module
		try:
			options = cfgCrawler.get(pluginInfo.name)
			crawlerModul.set_options(options)
		except Exception:
			log.error("Crawler module %s not found in configuration file", pluginInfo.name)  
			
		# If the crawler module is disabled in the config, skip it.
		if not options.enabled:
			continue
		
		try:
			log.debug("Run Crawler: " + pluginInfo.name)
			returnMap = crawlerModul.run()
			mapURL.update(returnMap)
		except Exception as e:
			log.error('Error (%s) in %s', e, pluginInfo.name)
	
	return mapURL

def runWorker(url):
	log.info("Worker URL: " + url)
	worker = Worker()
	worker.run(url)
		
def printRagpickerInfos(print_options=False):
	infolog = logging.getLogger("Info")
	infolog.info(color("RAGPICKER_VERSION: " + RAGPICKER_VERSION, RED))
	infolog.info(color("RAGPICKER_BUILD_DATE: " + RAGPICKER_BUILD_DATE, RED))
	infolog.info(color("RAGPICKER_ROOT: " + RAGPICKER_ROOT, RED))
	infolog.info("")
	
	pluginPlaces = ["crawler", "preProcessing", "processing", "reporting"]
	
	for place in pluginPlaces:
		infolog.info(color("%s| " % (place + " ").upper().ljust(14, '-'), MAGENTA))
		cfg = Config(os.path.join(RAGPICKER_ROOT, 'config', place + '.conf'))
		ragpickerPluginManager = PluginManager()
		ragpickerPluginManager.setPluginPlaces([place])
		ragpickerPluginManager.collectPlugins()
		
		for pluginInfo in sorted(ragpickerPluginManager.getAllPlugins(), key=lambda PluginInfo: PluginInfo.name):
			options = cfg.get(pluginInfo.name) 
			
			if options.enabled:
				infolog.info(color("%s V%s   %s", MAGENTA) % ("              |----[+] " + 
						pluginInfo.name.ljust(25), pluginInfo.version, pluginInfo.description))
				if print_options:
					for key, value in options.iteritems():
						if key != "enabled":
							infolog.info(color("                    |-- %s = %s", MAGENTA) % (key, str(value)))
			else:
				infolog.info(color("%s V%s   %s", BLUE) % ("              |----[-] " + 
						pluginInfo.name.ljust(25), pluginInfo.version, pluginInfo.description))
	
	infolog.info("")
	infolog.info("            %s %s" % (color("([+] = enabled)", MAGENTA), color("([-] = disabled)", BLUE)))
	infolog.info("")
	
	checkVersion()
				
	sys.stdout.flush()

def checkVersion():
	infolog = logging.getLogger("Info")
	infolog.info(color("Checking for Ragpicker updates...", RED))
	
	try:
		request = urllib2.Request(VERSION_URL)
		response = urllib2.urlopen(request, timeout=60)
	except (urllib2.URLError, urllib2.HTTPError):
		infolog.info(color("Failed! Unable to establish connection.", RED))
		return

	try:
		response_data = json.loads(response.read())
	except ValueError:
		infolog.info(color("Failed! Invalid response.", RED))
		return

	server_version = getServerVersion(response_data)
	current_version = getCurrentVersion()
	
	if server_version["major"] == current_version["major"] and server_version["minor"] == current_version["minor"] and server_version["build"] == current_version["build"]:
		infolog.info(color("You have the latest version", GREEN))
	else:
		infolog.info(color("Ragpicker version %s.%s.%s (%s) is available!" % (server_version["major"],
                                                                server_version["minor"],
                                                                server_version["build"],
                                                                server_version["date"]), RED))

def getCurrentVersion():
	version = RAGPICKER_VERSION.split(".")
	current_version = {}
	current_version["major"] = version[0]
	current_version["minor"] = version[1]
	current_version["build"] = version[2]
	return current_version

def getServerVersion(response_data):
	server_version = {}
	if response_data["ragpicker.build.major.number"]:
		server_version["major"] = response_data["ragpicker.build.major.number"]
	if response_data["ragpicker.build.minor.number"]:
		server_version["minor"] = response_data["ragpicker.build.minor.number"]
	if response_data["ragpicker.build.number"]:
		server_version["build"] = response_data["ragpicker.build.number"]
	if response_data["ragpicker.build.date"]:
		server_version["date"] = response_data["ragpicker.build.date"]
	return server_version

def color(text, colour=GREEN):
	if sys.platform == "win32" and os.getenv("TERM") != "xterm":
		return text
	return "\x1b[1;%dm" % (30 + colour) + text + "\x1b[0m"

if __name__ == "__main__":
	main()
