#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
ArduKey authserver

Copyright 2015 Bastian Raschke <bastian.raschke@posteo.de>
All rights reserved.
"""

import threading
import configparser
import os


class Configuration(object):
    """
    Configuration file reader.

    @attribute string __configurationFilePath
    The path to the configuration file.

    @attribute configParser __configParser
    The ConfigParser object.
    """

    __configurationFilePath = ''
    __configParser = None

    def __init__(self, configurationFilePath):
        """
        Constructor

        @attribute string configurationFilePath
        The path to the configuration file.
        """

        ## Check if path/file is readable
        if ( os.access(configurationFilePath, os.R_OK) == False ):
            raise ValueError('The configuration file "' + configurationFilePath + '" is not readable!')

        self.__configurationFilePath = configurationFilePath

        self.__configParser = configparser.ConfigParser()
        self.__configParser.read(self.__configurationFilePath)

    def __del__(self):
        """
        Destructor

        """

        pass

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

configurationFilePath = None

def setFilePath(filePath):
    """
    Sets the configuration filepath at module level.

    @return void
    """

    global configurationFilePath
    configurationFilePath = filePath

## Object instances on module level
moduleInstances = {}

def getInstance():
    """
    Singleton method to get instance at module level.

    @return Configuration
    """

    global moduleInstances

    ## Gets id of current thread
    currentThreadId = threading.current_thread().ident

    if ( currentThreadId not in moduleInstances ):
        moduleInstances[currentThreadId] = Configuration(configurationFilePath)

    return moduleInstances[currentThreadId]
