import os
import logging
import datetime
import simplejson

from core.abstracts import Processing

try:
	from yapsy.IPlugin import IPlugin
except ImportError:
	raise ImportError, 'Yapsy (Yet Another Plugin System) is required to run this program : http://yapsy.sourceforge.net'

log = logging.getLogger("Processing Teamcymru")

CMD = 'dig +short x.malware.hash.cymru.com TXT'

class Teamcymru(IPlugin, Processing):

	def run(self, objfile):
		self.key = "Teamcymru"
		self.score = -1

		try:
			value = self.submit(objfile.file.get_fileMd5())
			if value:
				malwarepercent = value.get("malwarepercent")
				
				self.score = 10
				
				if malwarepercent > 10 and malwarepercent < 30:
					self.score = 25		
				elif malwarepercent >= 30:
					self.score = 50   
			
			return value
		except (Exception) as e:
			log.error("The module \"Teamcymru\" returned the following error: %s" % e)		
			
		return

	def submit(self, md5):
		cmd = CMD.replace('x', md5)
		log.debug('Submit '+ cmd)
		result=os.popen(cmd)
		
		result=result.readlines()
		
		if len(result)> 0:		
			result=result[0]
			result=result.replace('\n','')
			result=result.replace('"','')
			if result != '127.0.0.2':
				timestamp=int(result.split(' ')[0])
				lastseen = datetime.datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
				malwarepercent=result.split(' ')[1]
				data = {"lastseen":lastseen,
						"malwarepercent":malwarepercent} #anti-virus package detection rate
				return data	
