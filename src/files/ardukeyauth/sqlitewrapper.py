#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
ArduKey authserver

Copyright 2015 Bastian Raschke <bastian.raschke@posteo.de>
All rights reserved.
"""

import threading
import sqlite3
import os


class SQLiteWrapper(object):
    """
    SQLite database wrapper class.

    @attribute sqlite3.Connection connection
    The database connection.

    @attribute sqlite3.Cursor cursor
    The database cursor.
    """

    connection = None
    cursor = None

    def __init__(self, databaseFilePath):
        """
        Constructor

        @attribute string databaseFilePath
        The path to the database file.
        """

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

        self.connection = None
        self.cursor = None

databaseFilePath = ''

def setFilePath(filePath):
    """
    Sets the database filepath at module level.

    @return void
    """

    global databaseFilePath
    databaseFilePath = filePath

## Object instances on module level
moduleInstances = {}

def getInstance():
    """
    Singleton method to get instance at module level.

    @return SQLiteWrapper
    """

    global moduleInstances

    ## Gets id of current thread
    currentThreadId = threading.current_thread().ident

    if ( currentThreadId not in moduleInstances ):
        moduleInstances[currentThreadId] = SQLiteWrapper(databaseFilePath)

    return moduleInstances[currentThreadId]
