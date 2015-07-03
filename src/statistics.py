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

import argparse
import logging

from utils.logo import logo 
from core.statistics import Statistics

log = logging.getLogger("Main")

if __name__ == '__main__':         
        
    parser = argparse.ArgumentParser(description='Ragpicker Statistics')
    subparsers = parser.add_subparsers(title='subcommands', description='valid subcommands', help='additional help')
   
    parser_long = subparsers.add_parser('long', help="Show statistics (long version)")
    parser_long.set_defaults(which='long')
    parser_short = subparsers.add_parser('short', help="Show statistics (short version)")
    parser_short.set_defaults(which='short')   
    parser_av = subparsers.add_parser('av', help="Show statistics (AV version)")
    parser_av.set_defaults(which='av')
    
    args = vars(parser.parse_args())
    
    logo()
    
    if args['which'] == 'long':
        Statistics().runStatisticsLong()
    elif args['which'] == 'short':
        Statistics().runStatisticsShort()
    elif args['which'] == 'av':
        Statistics().runStatisticsAV()