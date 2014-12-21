#!/usr/bin/env python3
# coding: utf-8

"""
ArduKey authserver
@author Bastian Raschke

Copyright 2014 Bastian Raschke
All rights reserved.
"""

import sqlite3
import threading
import os

from libraries.ConfigurationFile import ConfigurationFile


class SQLiteWrapper(object):
    """
    SQLite database wrapper class (multi thread usable).

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

        self.connect()

    def __del__(self):
        """
        Destructor

        """

        self.disconnect()

    def connect(self):
        """
        Connects to database.

        @return void
        """

        ## TODO: Path to file
        configurationFilePath = './ardukey-auth.conf'

        ## Reads from configuration file
        configuration = ConfigurationFile(configurationFilePath)

        databaseFilePath = configuration.readString('Default', 'database_file')

        ## Checks if path/file is writable
        if ( os.access(databaseFilePath, os.W_OK) == False ):
            raise Exception('The database file "' + databaseFilePath + '" is not writable!')

        self.connection = sqlite3.connect(databaseFilePath)
        self.cursor = self.connection.cursor()

    def disconnect(self):
        """
        Connects from database.

        @return void
        """

        ## Closes connection
        ## Important: Any uncommited change will be lost now
        if ( self.connection != None ):
            self.connection.close()
