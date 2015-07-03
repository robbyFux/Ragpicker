# Copyright (C) 2013-2015 Ragpicker Developers.
# This file is part of Ragpicker Malware Crawler - http://code.google.com/p/malware-crawler/

import ConfigParser


class Config:
    """Configuration file parser."""

    def __init__(self, cfg):
        """@param cfg: configuration file path."""
        config = ConfigParser.ConfigParser()
        config.read(cfg)

        for section in config.sections():
            setattr(self, section, Dictionary())
            for name, raw_value in config.items(section):
                try:
                    value = config.getboolean(section, name)
                except ValueError:
                    try:
                        value = config.getint(section, name)
                    except ValueError:
                        value = config.get(section, name)

                setattr(getattr(self, section), name, value)

    def get(self, section):
        """Get option.
        @param section: section to fetch.
        @raise Exception: if section not found.
        @return: option value.
        """
        try:
            return getattr(self, section)
        except AttributeError as e:
            raise Exception("Option %s is not found in configuration, error: %s" % (section, e))
        
    def getOption(self, section, option):
        """Get option.
        @param section: section to fetch, option: value of a specified option in section
        @raise Exception: if section not found.
        @return: option value.
        """
        try:
            return getattr(getattr(self, section), option)
        except AttributeError as e:
            raise Exception("Section %s is not found in configuration, error: %s" % (section, e))
            
class Dictionary(dict):
    """Ragpicker custom dict."""

    def __getattr__(self, key):
        return self.get(key, None)

    __setattr__ = dict.__setitem__
    __delattr__ = dict.__delitem__
