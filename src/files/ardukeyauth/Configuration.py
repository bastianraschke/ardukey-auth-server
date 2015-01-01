#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
ArduKey authserver
@author Philipp Meisberger <team@pm-codeworks.de>, Bastian Raschke <bastian.raschke@posteo.de>

Copyright 2014 Philipp Meisberger, Bastian Raschke
All rights reserved.
"""

import configparser
import threading
import os


## Path to configuration file
configurationFilePath = '/etc/ardukey-auth.conf'

class Configuration(object):
    """
    Configuration file parser and writer.

    @attribute dict<self> __instances
    Singleton instances.

    @attribute string __configParser
    The ConfigParser object.
    """

    __instances = {}
    __configParser = None

    @classmethod
    def getInstance(self):
        """
        Singleton method

        @return self
        """

        ## Gets ID of current thread
        currentThreadId = threading.current_thread().ident

        if ( currentThreadId not in self.__instances ):
            self.__instances[currentThreadId] = self()

        return self.__instances[currentThreadId]

    def __init__(self):
        """
        Constructor

        """

        ## Checks if path/file is readable
        if ( os.access(configurationFilePath, os.R_OK) == False ):
            raise ValueError('The configuration file "' + configurationFilePath + '" is not readable!')

        self.__configParser = configparser.ConfigParser()
        self.__configParser.read(configurationFilePath)

    def __del__(self):
        """
        Destructor

        """

        self.save()

    def save(self):
        """
        Writes modifications to configuration file.

        @return boolean
        """

        # Checks if path/file is writable
        if ( os.access(configurationFilePath, os.W_OK) == True ):

            f = open(configurationFilePath, 'w')
            self.__configParser.write(f)
            f.close()

            return True

        return False

    def readString(self, section, name):
        """
        Reads a string value.

        @param string section
        @param string name
        @return string
        """

        return self.__configParser.get(section, name)

    def writeString(self, section, name, value):
        """
        Writes a string value.

        @param string section
        @param string name
        @param string value
        @return void
        """

        self.__configParser.set(section, name, value)

    def readBoolean(self, section, name):
        """
        Reads a boolean value.

        @param string section
        @param string name
        @return boolean
        """

        return self.__configParser.getboolean(section, name)

    def readInteger(self, section, name):
        """
        Reads a decimal integer value.

        @param string section
        @param string name
        @return integer
        """

        ## Casts to integer (base 10)
        return int(self.readString(section, name), 10)

    def readList(self, section, name):
        """
        Reads a list.

        @param string section
        @param string name
        @return list
        """

        unpackedList = self.readString(section, name)
        return unpackedList.split(',')

    def writeList(self, section, name, value):
        """
        Writes a list.

        @param string section
        @param string name
        @param list value
        @return void
        """

        delimiter = ','
        self.__configParser.set(section, name, delimiter.join(value))

    def remove(self, section, name):
        """
        Removes a value.

        @param string section
        @param string name
        @return boolean
        """

        return self.__configParser.remove_option(section, name)

    def sectionExists(self, section):
        """
        Checks if a given section exists.

        @param string section
        @return boolean
        """

        return self.__configParser.has_section(section)

    def itemExists(self, section, name):
        """
        Checks if an item in a given section exists.

        @param string section
        @param string name
        @return boolean
        """

        return self.__configParser.has_option(section, name)

    def getSections(self):
        """
        Returns all sections as a list.

        @return list
        """

        return self.__configParser.sections()

    def getItems(self, section):
        """
        Returns all items of a sections as a list.

        @return list
        """

        return self.__configParser.items(section)
