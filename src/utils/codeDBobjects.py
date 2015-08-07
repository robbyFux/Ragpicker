#!/usr/bin/env python
# -*- coding: utf-8 -*-

import base64
import jsonpickle
import itertools
import mimetools
import mimetypes
from collections import OrderedDict

# Weil er es unter den Klassendefinitionen nicht findet
WANTSBASE64 = "True"

# Assert: keine/wenig Spezial-Abhaengigkeiten fuer import!

# String -> Dict
# Form: "key1:value1 ; ke2:value2; ..."
def returnDictfromString(csvStr):
    
    userDict = {}
    
    if csvStr:
        
        # Sonderzeichen ';' und ':' muss escaped sein (als ';;' oder '::') damit es durchkommt.
        
        # Ersetzen der escapten Zeichen durch temporaere Platzhalter.
        csvStr = csvStr.replace(";;","~~~") # Die werden gerettet.
        csvStr = csvStr.replace("::","§§§") # Die werden gerettet.
        
        csvStr = csvStr.replace("\\","/") # Das geht leider gar nicht mit dem Backslash.
        csvStr = csvStr.replace("\"","") # Das '"' geht leider auch nicht.
        csvStr = csvStr.replace("'","") # Vorsichthalber auch nicht.
        csvStr = csvStr.replace("{","") # Vorsichthalber auch nicht.
        csvStr = csvStr.replace("}","") # Vorsichthalber auch nicht.
        
        # Sanity check.
        if not (";" in csvStr): return {}
        if not (":" in csvStr): return {}

        keypairs = csvStr.split(";")

        for keypair in keypairs:
            if (keypair.count(":") == 1):
                # Der KEY
                key,pair = keypair.split(':')
                key = key.split()[0] # Kein Space im Key!
                key = key.strip().lower() # Mach Kleinbuchstaben daraus.
                # Im Key werden diese Steuerzeichen nicht geduldet.
                key.replace("~~~","")
                key.replace("§§§","")
                
                # Das VALUE
                value = pair.strip()
                if (value):
                    if (value != "None"):
                        # Originalstring wieder hergestellt.
                        value.replace("~~~",";")
                        value.replace("§§§",":")
                        userDict[key] = value
    return userDict

# Dict -> String
def returnDictToString(D):
    returnValue = ""

    for k in D:
        # eventuelle Steuerzeichen im VALUE escapen.
        # (und im KEY sind keine erlaubt.)
        D[k].replace(":","::")
        D[k].replace(";",";;")
        
        returnValue += "%s:%s;" % (k, D[k])

    return returnValue
    
    
def removeDuplicates(D_tags):
    
    D_new = D_tags.copy()
    
    # Duplikate raus
    for k,v in D_new.items():
        
        # Jedes Tag auf multiple Eintraege untersuchen.
        tokens = [x.strip().rstrip() for x in v.split("|")]
        if (not tokens): continue
        
        # Duplikate raus
        tokens = list(set(tokens))
        
        # Tag-Line wiederherstellen, ohne Duplikate.
        if (len(tokens) > 1):
            str_line = tokens[0]
            for t in tokens[1:]:
                str_line += " | %s " % (t)
                D_new[k] = str_line
            
        else:
            D_new[k] = tokens[0]
    
    return D_new
    

#author = "unknown"
#https://github.com/zmousm/ubnt-nagios-plugins/blob/master/MultiPartForm.py
class MultiPartForm(object):

    """Accumulate the data to be used when posting a form."""

    def __init__(self):
        self.form_fields = []
        self.files = []
        self.boundary = mimetools.choose_boundary()
        return

    def get_content_type(self):
        return 'multipart/form-data; boundary=%s' % self.boundary

    def add_field(self, name, value):
        """Add a simple field to the form data."""
        #Check for None-Values
        if value == None:
            value = ""
        self.form_fields.append((name, value))
        return

    def add_raw_file(self, fieldname, filename, fileHandle, mimetype=None):
        """Add a file to be uploaded."""
        body = fileHandle.read()
        if mimetype is None:
            mimetype = mimetypes.guess_type(filename)[0] or 'application/octet-stream'
        self.files.append((fieldname, filename, mimetype, body))
        return

    def add_file_data(self, fieldname, filename, file_data, mimetype=None):
        """Add a file to be uploaded."""
        if mimetype is None:
            mimetype = mimetypes.guess_type(filename)[0] or 'application/octet-stream'
        self.files.append((fieldname, filename, mimetype, file_data))
        return

    def add_file_data_b64(self, fieldname, filename, file_data, mimetype=None):
        """Add a file to be uploaded."""
        mimetype = ['application/octet-stream', 'Content-Transfer-Encoding: base64']
        self.files.append((fieldname, filename, '\r\n'.join(mimetype), base64.b64encode(file_data)))
        return

    def __str__(self):
        """Return a string representing the form data, including attached files."""
        # Build a list of lists, each containing "lines" of the
        # request.  Each part is separated by a boundary string.
        # Once the list is built, return a string where each
        # line is separated by '\r\n'.
        parts = []
        part_boundary = '--' + self.boundary

        # Add the form fields
        parts.extend(
            [ part_boundary,
              'Content-Disposition: form-data; name="%s"' % name,
              '',
              value,
            ]
            for name, value in self.form_fields
            )

        # Add the files to upload
        parts.extend(
            [ part_boundary,
              'Content-Disposition: file; name="%s"; filename="%s"' % \
                 (field_name, filename),
              'Content-Type: %s' % content_type,
              '',
              body,
            ]
            for field_name, filename, content_type, body in self.files
            )

        # Flatten the list and add closing boundary marker,
        # then return CR+LF separated data
        flattened = list(itertools.chain(*parts))
        flattened.append('--' + self.boundary + '--')
        flattened.append('')

        return '\r\n'.join(flattened)


# ---------------------------
# Malware-Objekt, enthaelt alle externen Parameter fuer einen Eintrag einer Malware in die Code-Datenbank.
class VOMalwareSample:

        VERTRAULICH_FREIGEGEBEN = 0
        VERTRAULICH_ABSPRECHEN = 1
        MAX_VERTRAULICH = 2
        
        NORMAL_MODE = 0
        USE_AS_PACKED = 1
        
        ARCH_X86 = "x86"
        ARCH_X64 = "x64"
        ARCH_IA64 = "ia64"

        def __init__(self,
                     sha256="",
                     fileName="",
                     binType="",
                     downloadDatestamp="",
                     vertraulich=VERTRAULICH_FREIGEGEBEN, # Da es sowieso nur begrenzt viele Leute mit Zugriff gibt, default 0.
                     architecture = "",
                     subsystem = "",
                     imphash = "",
                     pehash = "",
                     tags={},
                     media={},
                     s_sha256="",
                     s_sha1="",
                     s_md5="",
                     packed = NORMAL_MODE,   # overwrite flag fuer codescanner.
                     base64=False):

            # Sha256 Hash (str sha256)
            self._strsha256 = sha256

            # Urspruenglicher Name des Executables oder "" (str)
            self._strFileName = fileName

            # Dateityp (exe, dll, sys, elf, efi, bin, ...) (str mit 3 Bytes)
            self._strbinType = binType

            # Zeitstempel des Downloads (str timestamp)
            self._dtsDownloadDatestamp = downloadDatestamp

            # Ist das Sample vertraulich? (int)
            # 0 = nein. freigegeben,
            # 1 = ja. Unter bestimmten Auflagen/Absprachen eventuell erwaegbar.
            # 2 = ja. Niemals freigegeben.
            # (3+ = reserved)
            self._intVertraulich = vertraulich

            # 32-Bit, 64-Bit, I64 oder "" (str)
            self._strArchitecture = architecture
            
            # PE-Files vor allem. Z.B. WINDOWS_GUI oder NATIVE (str)
            self._strSubsystem = subsystem
            
            # Der imphash (import hash) von einem PE-File. Laenge 32 Bytes. (str md5)
            self._strImphash = imphash
            
            # Der pehash von einem PE-File. Laenge 40 Bytes. (str Sha1)
            self._strPehash = pehash

            # User-definierte Tags zum Sample als dictionary.
            # Die Tags koennen auch nur fuer dieses Sample oder wenige spezifisch sein.
            # Es dient sowohl als Zusatz-"Label" wie als user-definiertes Suchkriterium.
            # In der Code-Datenbank kann man spaeter nach "seinen" Tags suchen.
            # zB:
            # "Analyse" : "partiell" / "Analyse" : "noch keine durchgefuehrt"
            # "Kuerzel" : "Zeus" / "Kuerzel" : "TDL"
            # "targetedAttack" : "True" / "targetedAttack" : "False"
            # "Zeus-Version" : "4.05b"
            self._tags = tags

            self._media = media

            # Hashes of original packed file
            self._s_sha256 = s_sha256
            self._s_sha1 = s_sha1
            self._s_md5 = s_md5
            
            # Overwrite flag, welches Code-DB anweist, auch Samples mit wenig Code-Anteil aufzunehmen.
            self._intUsepacked = packed

            # bool base64, default ist False.
            self._boolBase64 = base64


        # Werte aus Request zusammenklauben. None-Werte sind unzulaessig.
        # Wird serverseitig verwendet.
        def fromRequest(self, http_request):
            self.setsha256(http_request.forms.get("sha256"))
            self.setFileName(http_request.forms.get("fileName"))
            self.setbinType(http_request.forms.get("binType"))
            self.setDownloadDatestamp(http_request.forms.get("downloadDatestamp"))
            self.setVertraulich(http_request.forms.get("vertraulich"))
            self.setArchitecture(http_request.forms.get("architecture"))
            self.setSubsystem(http_request.forms.get("subsystem"))
            self.setImphash(http_request.forms.get("imphash"))
            self.setPehash(http_request.forms.get("pehash"))
            self.setTags(http_request.forms.get("tags"))
            self.setMedia(http_request.forms.get("media"))
            self.set_s_sha256(http_request.forms.get("s_sha256"))
            self.set_s_sha1(http_request.forms.get("s_sha1"))
            self.set_s_md5(http_request.forms.get("s_md5"))
            self.setusepacked(http_request.forms.get("packed"))
            self.setBase64(http_request.forms.get("base64"))

        # Werte aus Malware-Objekt zu einem Multipart-Objekt zusammensetzen.
        # REM: Wird Client-Seitig verwendet und muss up-to-date gehalten werden!

        def toMultiPartForm(self):
            form = MultiPartForm()

            form.add_field('sha256', self.getsha256() or "") # str with 64 length
            form.add_field('fileName', self.getFileName() or "") # How the file was named, original name
            form.add_field('binType', self.getbinType() or "") # sys, exe, dll, efi, bin, ...
            form.add_field('downloadDatestamp', self.getDownloadDatestamp() or "") # Year:month:day hour:minute works best.
            form.add_field('vertraulich', str(self.getVertraulich()) or "") # int
            form.add_field('architecture', self.getArchitecture() or "")
            form.add_field('subsystem', self.getSubsystem() or "")
            form.add_field('imphash', self.getImphash() or "")
            form.add_field('pehash', self.getPehash() or "")
            form.add_field('tags', returnDictToString(self.getTags()) or "") # Tags, if any
            form.add_field('media', returnDictToString(self.getMedia()) or "") # Media, if any
            form.add_field('s_sha256', self.get_s_sha256() or "") # str with 64 length
            form.add_field('s_sha1', self.get_s_sha1() or "") # str with 40 length
            form.add_field('s_md5', self.get_s_md5() or "") # str with 32 length
            form.add_field('packed', str(self.getusepacked()) or "") # int
            form.add_field('base64', str(self.getBase64()) or "")  # bool
            return form

        def toDict(self):
            return {'sha256': self.getsha256() or "",
                    'fileName': self.getFileName() or "",
                    'binType': self.getbinType() or "",
                    'downloadDatestamp': self.getDownloadDatestamp() or "",
                    'vertraulich': str(self.getVertraulich()) or "",
                    'architecture': self.getArchitecture() or "",
                    'subsystem': self.getSubsystem() or "",
                    'imphash': self.getImphash() or "",
                    'pehash': self.getPehash() or "",
                    'tags': returnDictToString(self.getTags()) or "",
                    'media': returnDictToString(self.getMedia()) or "",
                    's_sha256': self.get_s_sha256() or "",
                    's_sha1': self.get_s_sha1() or "",
                    's_md5': self.get_s_md5() or "",
                    'packed': str(self.getusepacked()) or "",
                    'base64': str(self.getBase64()) or ""} 


        # Eigentlich ist alles > 0 erst mal vertraulich.
        # Habe die Restriktion strenger gestellt.
        def isVertraulich(self):
            if self._intVertraulich: return True
            return False


        # Nicht wirklich ausgefuellt. :o)
        def prints(self):
            print "\n------"
            print "Submitted Malware:"
            print "Sha256:" ,self.getsha256()
            print "Filename:", self.getFileName()
            print "bin type:", self.getbinType()
            print "Date:", self.getDownloadDatestamp()
            print "..."
            print "------\n"

        # Getter

        def getsha256(self):
            return self._strsha256

        def getFileName(self):
            return self._strFileName

        def getbinType(self):
            return self._strbinType

        def getDownloadDatestamp(self):
            return self._dtsDownloadDatestamp

        def getVertraulich(self):
            return self._intVertraulich

        def getArchitecture(self):
            return self._strArchitecture
            
        def getSubsystem(self):
            return self._strSubsystem
            
        def getImphash(self):
            return self._strImphash
            
        def getPehash(self):
            return self._strPehash

        def getTags(self):
            return self._tags

        def getMedia(self):
            return self._media

        def get_s_sha256(self):
            return self._s_sha256
            
        def get_s_sha1(self):
            return self._s_sha1
            
        def get_s_md5(self):
            return self._s_md5
            
        def getusepacked(self):
            return self._intUsepacked

        def getBase64(self):
            return self._boolBase64

        # Setter

        def setsha256(self, value):
            if (value):
                self._strsha256 = str(value)
            else: self._strsha256 = ""

        def setFileName(self, value):
            if (value):
                self._strFileName = str(value)
            else: self._strFileName = ""

        def setbinType(self, value):
            if (value):
                self._strbinType = str(value)
            else: self._strbinType = ""

        def setDownloadDatestamp(self, value):
            if (value):
                self._dtsDownloadDatestamp = str(value)
            else: self._dtsDownloadDatestamp = ""

        def setVertraulich(self, value):
            if value:
                value = str(value) # das sollte auf jedenfall ein String "1" oder "0" sein!
                if value.isdigit():
                    self._intVertraulich = int(value)
                    if (self._intVertraulich > self.MAX_VERTRAULICH):
                        self._intVertraulich = self.MAX_VERTRAULICH
                else:
                    self._intVertraulich = self.VERTRAULICH_FREIGEGEBEN

        def setArchitecture(self, value):
            if (value):
                self._strArchitecture = str(value)
                
                # -- Moeglicherweise zu streng --
                #~ if (("32-bit" in self._strArchitecture.lower()) or \
                    #~ ("x86" in self._strArchitecture.lower())):
                    #~ self._strArchitecture = ARCH_X86
                #~ if (("64-bit" in self._strArchitecture.lower()) or \
                    #~ (x64 in self._strArchitecture.lower())):
                    #~ self._strArchitecture = ARCH_X64
                #~ 
                #~ if not ((self._strArchitecture == ARCH_X86) or \
                        #~ (self._strArchitecture == ARCH_X64) or \
                        #~ (self._strArchitecture == ARCH_IA64)):
                    #~ self._strArchitecture = ""
            else:
                self._strArchitecture = ""
                
        def setSubsystem(self, value):
            if (value):
                self._strSubsystem = str(value)
            else:
                self._strSubsystem = ""
                
        def setImphash(self, value):
            if (value):
                self._strImphash = str(value)
            else:
                self._strImphash = ""
                
        def setPehash(self, value):
            if (value):
                self._strPehash = str(value)
            else:
                self._strPehash = ""

        def setTags(self, value):
            if value:
                if (type(value) is str): # string form
                    self._tags = returnDictfromString(value)
                elif (type(value) is dict):
                    self._tags = value # dict form
                else: self._tags = {}

            else:
                self._tags = {}

        def setMedia(self, value):
            if value:
                if (type(value) is str): # string form
                    self._media = returnDictfromString(value)
                elif (type(value) is dict):

                    # Search for keys with None-values.
                    for k,v in value.items():
                        if (v == "None") or (v == None):
                            del value[k]

                    self._media = value # dict form

                else: self._media = {}
            else:
                self._media = {}

        def set_s_sha256(self, value):
            if (value):
                value = str(value).rstrip()
                if (len(value) == 64):
                    self._s_sha256 = value
                else: self._s_sha256 = ""
            else:
                self._s_sha256 = ""
                
                
        def set_s_sha1(self, value):
            if (value):
                value = str(value).rstrip()
                if (len(value) == 40):
                    self._s_sha1 = value
                else: self._s_sha1 = ""
            else:
                self._s_sha1 = ""
                
        def set_s_md5(self, value):
            if (value):
                value = str(value).rstrip()
                if (len(value) == 32):
                    self._s_md5 = value
                else: self._s_md5 = ""
            else:
                self._s_md5 = ""
                
        def setusepacked(self, value):
            if value:
                value = str(value) # das sollte auf jedenfall ein String "1" oder "0" sein!
                if (value.isdigit()):
                    self._intUsepacked = int(value)
                else:
                    self._sintUsepacked = self.NORMAL_MODE
            else:
                self._intUsepacked = self.NORMAL_MODE
            

        def setBase64(self, value):
            value = str(value)
            if (value == WANTSBASE64):
                self._boolBase64 = True
            else: # Leere Strings, "0" oder alles andere.
                self._boolBase64 = False
