# Copyright (C) 2013-2015 Ragpicker Developers.
# This file is part of Ragpicker Malware Crawler - http://code.google.com/p/malware-crawler/

import logging
import os
import re
import subprocess
import time

from core.abstracts import Processing
from core.constants import RAGPICKER_ROOT
from utils.pyasn1 import dn
import utils.verifySigs.auth_data as auth_data
import utils.verifySigs.fingerprint as fingerprint
import utils.verifySigs.pecoff_blob as pecoff_blob


try:
    from yapsy.IPlugin import IPlugin
except ImportError:
    raise ImportError, 'Yapsy (Yet Another Plugin System) is required to run this program : http://yapsy.sourceforge.net'

log = logging.getLogger("ProcessingVerifySigs")

class HashValidationError(Exception):
    pass

class verifySigs(IPlugin, Processing):
    
    def run(self, objfile):
        self.key = "VerifySigs"
        self.score = -1
        sysinternalsEnabled = self.options.get("sysinternals_enabled", False)   
        result = {}
        
        try:
            auth_data = self._verifySigs(objfile.file.temp_file)
            # No Validation-Exeption
            if auth_data:
                result = self._getValueFromAuthData(auth_data)
        except HashValidationError, message:
            self.score = 15
            log.warn("ValidationError: %s", message)
            result["ValidationError"] = "Hash validation error"
        except Exception, message:
            log.warn("VerifySigs warning: %s" % message)
            # second chance with sysinternals sigcheck on wine
            if sysinternalsEnabled:
                try:
                    result = self._sysinternalsSigcheck(objfile.file.temp_file)
                except Exception, message:
                    log.error("Sysinternals Sigcheck Error: %s" % message)
                    result["ValidationError"] = message
            
        return result
        
    def _getValueFromAuthData(self, auth_data):
        result = {}
        
        result["ProgramName"] = auth_data.program_name
        result["ProgramURL"] = auth_data.program_url
        result["Issuer"] = self._issuerParser(str(auth_data.signing_cert_id))
        for (issuer, serial), cert in auth_data.certificates.items():
            subject = cert[0][0]['subject']
            subject_dn = dn.DistinguishedName.TraverseRdn(subject[0])
            result["PublisherCN"] = subject_dn['CN']
            result["PublisherO"] = subject_dn['O']
            not_before_time = self._formatTime(cert[0][0]['validity']['notBefore'])
            not_after_time = self._formatTime(cert[0][0]['validity']['notAfter'])
            result["NotBefore"] = not_before_time
            result["NotAfter"] = not_after_time
            break
        
        return result
        
    def _verifySigs(self, filePath):    
        """
        Verify-sigs - requires pyasn1 & m2crypto (apt-get insatll python-pyasn1 python-m2crypto)
        """
        with open(filePath, 'rb') as f:
            fingerprinter = fingerprint.Fingerprinter(f)
            is_pecoff = fingerprinter.EvalPecoff()
            fingerprinter.EvalGeneric()
            results = fingerprinter.HashIt()
    
            if is_pecoff:
                # using a try statement here because of: http://code.google.com/p/verify-sigs/issues/detail?id=2
                try:
                    fingerprint.FindPehash(results)
                except Exception, msg:
                    # Fehler bei Hashvalidierung
                    log.warn("Hash validation error: %s" % msg)
                    raise HashValidationError("Hash validation error: %s" % msg)
            
            signed_pecoffs = [x for x in results if x['name'] == 'pecoff' and 'SignedData' in x]
            
            if not signed_pecoffs:
                # Keine Signatur
                log.debug('This PE/COFF binary has no signature. Exiting.')
                return None
            
            auth_data = self._validate(signed_pecoffs)
            
            return auth_data
    
    def _validate(self, signed_pecoffs):
        signed_pecoff = signed_pecoffs[0]
        signed_datas = signed_pecoff['SignedData']
        signed_data = signed_datas[0]
        blob = pecoff_blob.PecoffBlob(signed_data)
        auth = auth_data.AuthData(blob.getCertificateBlob())
        content_hasher_name = auth.digest_algorithm().name
        computed_content_hash = signed_pecoff[content_hasher_name]

        auth.ValidateAsn1()
        auth.ValidateHashes(computed_content_hash)
        auth.ValidateSignatures()
        auth.ValidateCertChains(time.gmtime())
        
        return auth
    
    def _formatTime(self, cert_time):
        cert_time = cert_time.ToPythonEpochTime()
        cert_time = time.strftime("%d.%m.%Y %H:%M:%S", time.gmtime(cert_time))
        return "%s UTC" % cert_time
        
    def _issuerParser(self, issuedString):
        pattern = re.compile("'O':\s'(.*?)'.*", re.IGNORECASE)
        rpdFind = re.findall(pattern, issuedString)
        
        for i in rpdFind:
            issuer = i
          
        return issuer
    
    def _sysinternalsSigcheck(self, filePath):
        wine = self.options.get("wine", "/usr/bin/wine")
        sigcheck = os.path.join(RAGPICKER_ROOT, 'utils', 'verifySigs', 'sigcheck.exe')
        cmd = wine + ' ' + sigcheck + ' -q -a ' + filePath
        
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
        (stdout, stderr) = process.communicate()
        
        stdout = stdout.decode('utf-8', 'ignore')
        
        if stdout:
            result = self._parseSysinternalsSigcheck(stdout)
            log.debug("sysinternalsSigcheck = " + str(result))
        else: 
            raise Exception(stderr)
        
        return result
    
    def _parseSysinternalsSigcheck(self, stdout):
        result = {}
        
        rpd = re.compile('\sPublisher:\s(.+)', re.IGNORECASE)
        rpdFind = re.findall(rpd, stdout)
        
        for r in rpdFind:
            result["PublisherO"] = r.replace("\r", "")
            
        rpd = re.compile('\sProduct:\s(.+)', re.IGNORECASE)
        rpdFind = re.findall(rpd, stdout)
        
        for r in rpdFind:
            result["ProgramName"] = r
    
        rpd = re.compile('\sSigning date:\s(.+)', re.IGNORECASE)
        rpdFind = re.findall(rpd, stdout)
        
        for r in rpdFind:
            result["SigningDate"] = r
        
        return result
