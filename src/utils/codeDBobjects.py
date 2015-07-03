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
        # Sanity check.
        if not (";" in csvStr): return {}

        keypairs = csvStr.split(";")

        for keypair in keypairs:
            if (keypair.count(":") == 1):
                key,pair = keypair.split(':')
                key = key.split()[0] # Kein Space im Key!
                key = key.strip().lower() # Kleinbuchstaben!
                pair = pair.strip().replace("|","")
                if (pair):
                    if (pair != "None"):
                        userDict[key] = pair
    return userDict

# Dict -> String
def returnDictToString(D):
    returnValue = ""

    for k in D:
        returnValue += "%s:%s" % (k, D[k])
        returnValue += "; "

    return returnValue

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
        VERTRAULICH_VERTRAULICH = 2

        def __init__(self,
                     sha256="",
                     fileName="",
                     binType="",
                     downloadDatestamp="",
                     vertraulich=VERTRAULICH_FREIGEGEBEN, # Da es sowieso nur begrenzt viele Leute mit Zugriff gibt, default 0.
                     downloadHostname="",
                     downloadIP="",
                     GeolocationHost="",
                     GeolocationSelf="",
                     tags={},
                     media={},
                     orighash="",
                     usepacked = 0, # overwrite flag fuer codescanner.
                     base64=False):

            # Sha256 Hash
            self._strsha256 = sha256

            # Urspruenglicher Name des Executables, sonst "unknown".
            self._strFileName = fileName

            # Dateityp (exe, dll, sys, elf, efi, bin, ...)
            self._strbinType = binType

            # Zeitstempel des Downloads
            self._dtsDownloadDatestamp = downloadDatestamp

            # 0 = nein. freigegeben,
            # 1 = ja. Unter bestimmten Auflagen/Absprachen eventuell erwaegbar.
            # 2 = ja. Niemals freigegeben.
            # (3+ = reserved)
            self._intVertraulich = vertraulich

            # Von welcher Domain wurde das Sample geladen
            self._strDownloadHostname = downloadHostname

            # IP von Host
            self._strDownloadIP = downloadIP

            # Geoinformation von Host
            self._strGeolocationHost = GeolocationHost

            # Eigene Geo-Location
            self._strGeolocationSelf = GeolocationSelf

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

            # Hash of original packed file
            self._orighash = orighash
            
            # Overwrite flag, welches Code-DB anweist, auch Samples mit wenig Code-Anteil aufzunehmen.
            self._intUsepacked = usepacked

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
            self.setDownloadHostname(http_request.forms.get("downloadHostname"))
            self.setDownloadIP(http_request.forms.get("downloadIP"))
            self.setGeolocationHost(http_request.forms.get("GeolocationHost"))
            self.setGeolocationSelf(http_request.forms.get("GeolocationSelf"))
            self.setTags(http_request.forms.get("tags"))
            self.setMedia(http_request.forms.get("media"))
            self.setOrighash(http_request.forms.get("orighash"))
            self.setusepacked(http_request.forms.get("usepacked"))
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
            form.add_field('downloadHostname', self.getDownloadHostname() or "") # where did you get it?
            form.add_field('downloadIP', self.getDownloadIP() or "") # where did you get it (numerical version)
            form.add_field('GeolocationHost', self.getGeolocationHost() or "") # Can you provide some geo information?
            form.add_field('GeolocationSelf', self.getGeolocationSelf() or "") # Location you are promoting to the internet.
            form.add_field('tags', returnDictToString(self.getTags()) or "") # Tags, if any
            form.add_field('media', returnDictToString(self.getMedia()) or "") # Media, if any
            form.add_field('orighash', self.getOrighash() or "") # str with 64 length
            form.add_field('usepacked', str(self.getusepacked()) or "") # int
            form.add_field('base64', str(self.getBase64()) or "")  # bool
            return form


        # Eigentlich ist alles > 0 erst mal vertraulich.
        # Habe die Restriktion strenger gestellt.
        def isVertraulich(self):
            if self._intVertraulich: return True
            return False

        def prints(self):
            print "\n------"
            print "VOMalware Instance:"
            print "Base64:", self.getBase64()
            print "Sha256:", self.getsha256()
            print "orighash:", self.getOrighash()
            print "Filename:", self.getFileName()
            print "bin type:", self.getbinType()
            print "Date:", self.getDownloadDatestamp()
            print "From host:", self.getDownloadHostname()
            print "IP:", self.getDownloadIP()
            print "Host location:", self.getGeolocationHost()
            print "Own location:", self.getGeolocationSelf()
            print "Media:"
            D = self.getMedia()
            for k,v in D.items():
                print "   ", k, ":", v, " "
            print "Tags:"
            D = self.getTags()
            for k,v in D.items():
                print "   ", k, ":", v, " "
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

        def getDownloadHostname(self):
            return self._strDownloadHostname

        def getDownloadIP(self):
            return self._strDownloadIP

        def getGeolocationHost(self):
            return self._strGeolocationHost

        def getGeolocationSelf(self):
            return self._strGeolocationSelf

        def getTags(self):
            return self._tags

        def getMedia(self):
            return self._media

        def getOrighash(self):
            return self._orighash
            
        def getusepacked(self):
            return self._intUsepacked

        def getBase64(self):
            return self._boolBase64

        # Setter

        def setsha256(self, value):
            if (value):
                self._strsha256 = value
            else: self._strsha256 = ""

        def setFileName(self, value):
            if (value):
                self._strFileName = value
            else: self._strFileName = ""

        def setbinType(self, value):
            if (value):
                self._strbinType = value
            else: self._strbinType = ""

        def setDownloadDatestamp(self, value):
            if (value):
                self._dtsDownloadDatestamp = value
            else: self._dtsDownloadDatestamp = ""

        def setVertraulich(self, value):
            if value:
                value = str(value) # das sollte auf jedenfall ein String "1" oder "0" sein!
                if value.isdigit():
                    self._intVertraulich = int(value)
                else:
                    self._intVertraulich = self.VERTRAULICH_FREIGEGEBEN

        def setDownloadHostname(self, value):
            if (value):
                self._strDownloadHostname = value
            else: self._strDownloadHostname = ""

        def setDownloadIP(self, value):
            if (value):
                self._strDownloadIP = value
            else: self._strDownloadIP = ""

        def setGeolocationHost(self, value):
            if (value):
                self._strGeolocationHost = value
            else: self._strGeolocationHost = ""

        def setGeolocationSelf(self, value):
            if (value):
                self._strGeolocationSelf = value
            else: self._strGeolocationSelf = ""

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

        def setOrighash(self, value):
            if (value):
                value = value.rstrip()
                if (len(value) == 64):
                    self._orighash = value
                else: self._orighash = ""
            else:
                self._orighash = ""
                
        def setusepacked(self, value):
            if value:
                value = str(value) # das sollte auf jedenfall ein String "1" oder "0" sein!
                if (value.isdigit()):
                    self._intUsepacked = int(value)
                else:
                    self._sintUsepacked = 0

        def setBase64(self, value):
            if (value == WANTSBASE64):
                self._boolBase64 = True
            else: # Leere Strings, "0" oder alles andere.
                self._boolBase64 = False
