#!/usr/bin/env python3
# coding: utf-8

"""
ArduKey authserver
@author Philipp Meisberger, Bastian Raschke

Copyright 2014 Philipp Meisberger, Bastian Raschke
All rights reserved.
"""

import configparser
import os


class ConfigurationFile(object):
    """
    Configuration file parser and writer.

    @attribute dict<self> __instances
    Singleton instances.

    @attribute string __filePath
    The path to configuration file.

    @attribute boolean __readOnly
    Flag that indicates configuration file will be not modified.

    @attribute string __configParser
    The ConfigParser object.
    """

    __instances = {}

    __filePath = None
    __readOnly = False
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

    def __init__(self, filePath, readOnly = False):
        """
        Constructor

        @param string filePath
        The path to configuration file.

        @param boolean readOnly
        Flag that indicates configuration file will be not modified.
        """

        ## Checks if path/file is readable
        if ( os.access(filePath, os.R_OK) == False ):
            raise ValueError('The configuration file "' + filePath + '" is not readable!')

        if ( type(readOnly) != bool ):
            raise ValueError('The given flag readOnly must be boolean!')

        self.__filePath = filePath
        self.__readOnly = readOnly

        self.__configParser = configparser.ConfigParser()
        self.__configParser.read(filePath)

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

        if ( self.__readOnly == True ):
            return False

        # Checks if path/file is writable
        if ( os.access(self.__filePath, os.W_OK) == True ):

            f = open(self.__filePath, 'w')
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
