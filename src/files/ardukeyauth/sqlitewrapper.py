#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
ArduKey authserver

Copyright 2015 Bastian Raschke <bastian.raschke@posteo.de>
All rights reserved.
"""

import sqlite3
import threading
import os

import ardukeyauth.configreader


class SQLiteWrapper(object):
    """
    SQLite database wrapper class.

    @attribute dict<self> __instances
    Singleton instances.

    @attribute sqlite3.Connection connection
    The database connection.

    @attribute sqlite3.Cursor cursor
    The database cursor.
    """

    __instances = {}
    connection = None
    cursor = None

    @classmethod
    def getInstance(self):
        """
        Singleton method

        @return Database
        """

        ## Gets id of current thread
        currentThreadId = threading.current_thread().ident

        if ( currentThreadId not in self.__instances ):
            self.__instances[currentThreadId] = self()

        return self.__instances[currentThreadId]

    def __init__(self):
        """
        Constructor

        """

        ## Get database file from config
        configReader = ardukeyauth.configreader.ConfigReader()
        databaseFilePath = configReader.get('database_file')

        ## Check if path/file is writable
        if ( os.access(databaseFilePath, os.W_OK) == False ):
            raise ValueError('The database file "' + databaseFilePath + '" is not writable!')

        self.connection = sqlite3.connect(databaseFilePath)
        self.cursor = self.connection.cursor()

    def __del__(self):
        """
        Destructor

        """

        ## Close connection (all uncommited changes will be lost)
        if ( self.connection is not None ):
            self.connection.close()
