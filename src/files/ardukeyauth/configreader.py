#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
ArduKey authserver

Copyright 2015 Bastian Raschke <bastian.raschke@posteo.de>
All rights reserved.
"""

import configparser
import os


class ConfigReader(object):
    """
    Configuration file reader.

    @attribute string __filePath
    The path to the configuration file.

    @attribute configParser __configParser
    The ConfigParser object.
    """

    __filePath = ''
    __configParser = None

    def __init__(self, filePath = '/etc/ardukey-auth-server.conf'):
        """
        Constructor

        @attribute string filePath
        The path to the configuration file.
        """

        ## Check if path/file is readable
        if ( os.access(filePath, os.R_OK) == False ):
            raise ValueError('The configuration file "' + filePath + '" is not readable!')

        self.__filePath = filePath

        self.__configParser = configparser.ConfigParser()
        self.__configParser.read(self.__filePath)

    def get(self, key, default = None):
        """
        Get a option by key.

        @param string key
        The option key.

        @param object default
        If no option is found, return default value instead.

        @return object
        """

        return self.__configParser.get('DEFAULT', key, fallback=default)
