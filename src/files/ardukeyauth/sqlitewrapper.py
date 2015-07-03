#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
ArduKey auth-server

Copyright 2015 Bastian Raschke <bastian.raschke@posteo.de>
All rights reserved.
"""

import threading
import sqlite3
import os


class SQLiteWrapper(object):
    """
    SQLite database wrapper class.

    @attribute str __databaseFilePath
    The path to the database file.

    @attribute sqlite3.Connection connection
    The database connection.

    @attribute sqlite3.Cursor cursor
    The database cursor.
    """

    def __init__(self):
        """
        Constructor

        """

        self.__databaseFilePath = ''
        self.connection = None
        self.cursor = None

    def setFilePath(self, databaseFilePath):
        """
        Set path to the database file.

        @attribute str databaseFilePath
        The path to the database file.

        @return void
        """

        ## Check if path/file is writable
        if ( os.access(databaseFilePath, os.W_OK) == False ):
            raise ValueError('The database file "' + databaseFilePath + '" is not writable!')

        self.__databaseFilePath = databaseFilePath

        self.connection = sqlite3.connect(databaseFilePath)
        self.cursor = self.connection.cursor()

    def __del__(self):
        """
        Destructor

        """

        ## Close connection (all uncommited changes will be lost)
        if ( self.connection is not None ):
            self.connection.close()

        self.connection = None
        self.cursor = None

## Lock object to provide mutal exclusion
mutexLock = threading.Lock()

## Object instances on module level
moduleInstances = {}

def getInstance():
    """
    Singleton method to get instance at module level.

    @return SQLiteWrapper
    """

    try:
        mutexLock.acquire()

        global moduleInstances

        ## Get id of current thread
        currentThreadId = threading.current_thread().ident

        if ( currentThreadId not in moduleInstances ):
            moduleInstances[currentThreadId] = SQLiteWrapper()

        returnValue = moduleInstances[currentThreadId]

    finally:
        mutexLock.release()

    return returnValue
