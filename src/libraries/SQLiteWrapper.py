#!/usr/bin/env python3

"""
ArduKey authserver
@author Bastian Raschke

Copyright 2014 Bastian Raschke.
All rights reserved.
"""

import sqlite3
import threading

## TODO
import os


class SQLiteWrapper(object):
    """
    SQLite 2 database wrapper class (multi thread usable).

    @attribute dict<Database> __instances
    Singleton instances.

    @attribute string databaseFile
    The file containing database.

    @attribute sqlite3.Connection connection
    The database connection.

    @attribute sqlite3.Cursor cursor
    The database cursor.
    """

    __instances = {}

    ## TODO
    ## databaseFile = '/var/ardukey-auth/ardukey-auth.sqlite'
    databaseFile = os.path.dirname(os.path.realpath(__file__)) + '/ardukey-auth.sqlite'
    connection = None
    cursor = None

    @classmethod
    def getInstance(self):
        """
        Singleton method

        @return Database
        """

        ## Gets ID of current thread
        currentThreadID = threading.current_thread().ident

        if ( currentThreadID not in self.__instances ):
            self.__instances[currentThreadID] = self()

        return self.__instances[currentThreadID]

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

        ## Checks if path/file is writable
        if ( os.access(self.databaseFile, os.W_OK) == False ):
            raise Exception('The database file "' +self.databaseFile + '" is not writable!')

        self.connection = sqlite3.connect(self.databaseFile)
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
