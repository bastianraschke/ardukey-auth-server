#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
ArduKey authserver
@author Bastian Raschke <bastian.raschke@posteo.de>

Copyright 2014 Bastian Raschke
All rights reserved.
"""

import sqlite3
import threading
import os

import ardukeyauth.configuration

class SQLiteWrapper(object):
    """
    SQLite database wrapper class.

    @attribute string __filePath
    The path to the database file.

    @attribute sqlite3.Connection connection
    The database connection.

    @attribute sqlite3.Cursor cursor
    The database cursor.
    """

    __filePath = ''
    connection = None
    cursor = None

    def __init__(self, filePath):
        """
        Constructor

        @attribute string __filePath
        The path to the database file.
        """

        ## Checks if path/file is writable
        if ( os.access(filePath, os.W_OK) == False ):
            raise ValueError('The database file "' + filePath + '" is not writable!')

        self.__filePath = filePath

        self.connection = sqlite3.connect(self.__filePath)
        self.cursor = self.connection.cursor()

    def __del__(self):
        """
        Destructor

        """

        ## Closes connection
        ## Important: Any uncommited change will be lost now
        if ( self.connection is not None ):
            self.connection.close()

## Loads database file
databaseFilePath = './ardukey-auth.sqlite'
database = Database(databaseFilePath)


print(ardukeyauth.configuration.getInstance())
