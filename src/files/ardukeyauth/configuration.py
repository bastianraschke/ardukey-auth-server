#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
ArduKey authserver
@author Bastian Raschke <bastian.raschke@posteo.de>

Copyright 2015 Bastian Raschke
All rights reserved.
"""

import configparser
import os

class Configuration(object):
    """
    Configuration file parser and writer.

    @attribute string __filePath
    The path to the configuration file.

    @attribute configparser __configParser
    The ConfigParser object.
    """

    __filePath = ''
    __configParser = None

    def __init__(self, filePath):
        """
        Constructor

        @attribute string filePath
        The path to the configuration file.
        """

        ## Checks if path/file is readable
        if ( os.access(filePath, os.R_OK) == False ):
            raise ValueError('The configuration file "' + filePath + '" is not readable!')

        self.__filePath = filePath

        self.__configParser = configparser.ConfigParser()
        self.__configParser.read(self.__filePath)

    def __del__(self):
        """
        Destructor

        """

        pass

    def get(self, section, name):
        """
        Reads a string value.

        @param string section
        @param string name
        @return string
        """

        return self.__configParser.get(section, name)

def getInstance():
    """
    Simply delegate the object at module level.

    @return Configuration
    """

    ## Loads configuration file
    configurationFilePath = './ardukey-auth.conf'
    return Configuration(configurationFilePath)
