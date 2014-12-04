#!/usr/bin/env python3

"""
ArduKey authserver
@author Bastian Raschke, Philipp Meisberger

Copyright 2014 Bastian Raschke, Philipp Meisberger.
All rights reserved.
"""

import sqlite3
import threading

from classes.Config import *


class Database(object):
    """
    SQLite database wrapper class (multi thread usable).

    @attribute dict<Database> __instances
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

        ## Gets current thread's id
        currentThreadID = threading.current_thread().ident

        if ( currentThreadID not in self.__instances ):
            self.__instances[currentThreadID] = Database()

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

        databaseFile = '/var/safehousepi/safehousepi.sqlite'

        ## Checks if path/file is writable
        if ( os.access(databaseFile, os.W_OK) == False ):
            raise Exception('The database file "' + databaseFile + '" is not writable!')

        self.connection = sqlite3.connect(databaseFile)
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
