# Copyright (C) 2013-2015 Ragpicker Developers.
# This file is part of Ragpicker Malware Crawler - http://code.google.com/p/malware-crawler/
# coding: utf-8

"""
Converts a native Python dictionary into an XML string. Supports int, float, str, unicode, list, dict and arbitrary nesting.
"""

from __future__ import unicode_literals

from random import randint
import collections
import logging
from xml.dom.minidom import parseString

# python 3 doesn't have a unicode type
try:
    unicode
except:
    unicode = str

log = logging.getLogger(__name__)

ids = [] # initialize list of unique ids

def make_id(element, start=100000, end=999999):
    """Returns a random integer"""
    return '%s_%s' % (element, randint(start, end))

def get_unique_id(element):
    """Returns a unique id for a given element"""
    this_id = make_id(element)
    dup = True
    while dup == True:
        if this_id not in ids:
            dup = False
            ids.append(this_id)
        else:
            this_id = make_id(element)
    return ids[-1]


def xml_escape(s):
    if type(s) in (str, unicode):
        s = s.replace('&',  '&amp;')
        s = s.replace('"',  '&quot;')
        s = s.replace('\'', '&apos;')
        s = s.replace('<',  '&lt;')
        s = s.replace('>',  '&gt;')
    return s

def make_attrstring(attr):
    """Returns an attribute string in the form key="val" """
    attrstring = ' '.join(['%s="%s"' % (k, v) for k, v in attr.items()])
    return '%s%s' % (' ' if attrstring != '' else '', attrstring)

def key_is_valid_xml(key):
    """Checks that a key is a valid XML name"""
    test_xml = '<?xmlString version="1.0" encoding="UTF-8" ?><%s>foo</%s>' % (key, key)
    try: 
        parseString(test_xml)
        return True
    except Exception: #minidom does not implement exceptions well
        return False

def convert(obj, ids, parent='root'):
    """Routes the elements of an object to the right function to convert them based on their data type"""
    log.debug('Inside convert(). obj type is: %s' % (type(obj).__name__))
    if type(obj) in (int, float, str, unicode):
        return convert_kv('item', obj)
    if hasattr(obj, 'isoformat'):
        return convert_kv('item', obj.isoformat())
    if type(obj) == bool:
        return convert_bool('item', obj)
    if obj == None:
        return convert_none('item', '')
    if isinstance(obj, dict):
        return convert_dict(obj, ids, parent)
    if type(obj) in (list, set, tuple) or isinstance(obj, collections.Iterable):
        return convert_list(obj, ids, parent)
    raise TypeError('Unsupported data type: %s (%s)' % (obj, type(obj).__name__))
    
def convert_dict(obj, ids, parent):
    """Converts a dict into an XML string."""
    log.debug('Inside convert_dict(): obj type is: %s' % (type(obj).__name__))
    output = []
    addline = output.append
        
    for k, v in obj.items():
        log.debug('Looping inside convert_dict(): k=%s, type(v)=%s' % (k, type(v).__name__))
        try:
            if k.isdigit():
                k = 'n%s' % (k)
        except:
            if type(k) in (int, float):
                k = 'n%s' % (k)
        this_id = get_unique_id(parent)
        attr = {} if ids == False else {'id': '%s' % (this_id) }
        
        if type(v) in (int, float, str, unicode):
            addline(convert_kv(k, v, attr))
        elif hasattr(v, 'isoformat'): # datetime
            addline(convert_kv(k, v.isoformat(), attr))
        elif type(v) == bool:
            addline(convert_bool(k, v, attr))
        elif isinstance(v, dict):
            addline('  <%s type="dict"%s>%s</%s>\n' % (
                k, make_attrstring(attr), convert_dict(v, ids, k), k)
            )
        elif type(v) in (list, set, tuple) or isinstance(v, collections.Iterable):
            addline('  <%s type="list"%s>%s</%s>\n' % (
                k, make_attrstring(attr), convert_list(v, ids, k), k)
            )
        elif v is None:
            addline(convert_none(k, v, attr))
        else:
            raise TypeError('Unsupported data type: %s (%s)' % (obj, type(obj).__name__))
    return ''.join(output)

def convert_list(items, ids, parent):
    """Converts a list into an XML string."""
    log.debug('Inside convert_list()')
    output = []
    addline = output.append
    this_id = get_unique_id(parent)
    for i, item in enumerate(items):
        log.debug('Looping inside convert_list(): item=%s, type=%s' % (item, type(item).__name__))
        attr = {} if ids == False else {
            'id': '%s_%s' % (this_id, i+1) 
        }
        if type(item) in (int, float, str, unicode):
            addline(convert_kv('item', item, attr))
        elif hasattr(item, 'isoformat'): # datetime
            addline(convert_kv('item', item.isoformat(), attr))
        elif type(item) == bool:
            addline(convert_bool('item', item, attr))
        elif isinstance(item, dict):
            addline('  <item type="dict">%s</item>\n' % (convert_dict(item, ids, parent)))
        elif type(item) in (list, set, tuple) or isinstance(item, collections.Iterable):
            addline('  <item type="list"%s>%s</item>\n' % (make_attrstring(attr), convert_list(item, ids, 'item')))
        elif item == None:
            addline(convert_none('item', None, attr))
        else:
            raise TypeError('Unsupported data type: %s (%s)' % (item, type(item).__name__))
    return ''.join(output)

def convert_kv(key, val, attr={}):
    """Converts an int, float or string into an XML element"""
    log.debug('Inside convert_kv(): k=%s, type(v) is: %s' % (key, type(val).__name__))
    key = key.replace(' ', '_') # replace spaces with underscores
    if key_is_valid_xml(key) == False:
        attr['name'] = key
        key = "key"
    attrstring = make_attrstring(attr)
    return '  <%s type="%s"%s>%s</%s>\n' % (
        key, type(val).__name__ if type(val).__name__ != 'unicode' else 'str', 
        attrstring, xml_escape(val), key
    )

def convert_bool(key, val, attr={}):
    """Converts a boolean into an XML element"""
    log.debug('Inside convert_bool(): key=%s, type(val) is: %s' % (key, type(val).__name__))
    key = key.replace(' ', '_') # replace spaces with underscores
    if key_is_valid_xml(key) == False:
        attr['name'] = key
        key = "key"
    attrstring = make_attrstring(attr)
    return '  <%s type="bool"%s>%s</%s>\n' % (key, attrstring, unicode(val).lower(), key)

def convert_none(key, val, attr={}):
    """Converts a null value into an XML element"""
    log.debug('Inside convert_none(): key=%s' % (key))
    key = key.replace(' ', '_') # replace spaces with underscores
    if key_is_valid_xml(key) == False:
        attr['name'] = key
        key = "key"
    attrstring = make_attrstring(attr)
    return '  <%s type="null"%s></%s>\n' % (key, attrstring, key)

def dicttoxml(obj, root=True, ids=False):
    """Converts a python object into XML"""
    log.debug('Inside dicttoxml(): type(obj) is: %s' % (type(obj).__name__))
    output = []
    addline = output.append
    if root == True:
        addline('<?xmlString version="1.0" encoding="UTF-8" ?>\n')
        addline('<ragpicker>\n%s</ragpicker>\n' % (convert(obj, ids, parent='root')))
    else:
        addline(convert(obj, ids, parent=''))
    return ''.join(output)