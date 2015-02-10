#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sqlite3


connection = sqlite3.connect('/home/bastian/Desktop/a.sqlite')
cursor = connection.cursor()

"""
cursor.execute(
    '''
    CREATE TABLE ARDUKEY
    (
      publicid TEXT(12) PRIMARY KEY,
      secretid TEXT(12) NOT NULL,
      counter INTEGER(5) NOT NULL DEFAULT 0,
      sessioncounter INTEGER(3) NOT NULL DEFAULT 0,
      timestamp INTEGER(8) DEFAULT 0,
      aeskey TEXT(32) NOT NULL,
      modified DATE,
      created DATE,
      enabled INTEGER(1) NOT NULL DEFAULT 1
    );
    ''', [
])
connection.commit()

cursor.execute(
    '''
    CREATE TRIGGER UPDATE_ARDUKEY BEFORE UPDATE ON ARDUKEY
        BEGIN
           UPDATE ARDUKEY SET modified = DATETIME('now', 'localtime')
           WHERE rowid = new.rowid;
        END;
    ''', [
])
connection.commit()

cursor.execute(
    '''
    CREATE TRIGGER INSERT_ARDUKEY AFTER INSERT ON ARDUKEY
        BEGIN
           UPDATE ARDUKEY SET modified = DATETIME('now', 'localtime')
           WHERE rowid = new.rowid;
        END;
    ''', [
])
connection.commit()

cursor.execute(
    '''

    INSERT INTO ARDUKEY(publicid, secretid, aeskey)
    VALUES(?, ?, ?);
    ''', [
    'publicId',
    'secretId',
    'aesKey',
])
connection.commit()

"""









cursor.execute(
    '''
    SELECT secretid, modified
    FROM ARDUKEY
    ''', [
])

rows = cursor.fetchall()

print(rows)




cursor.execute(
    '''
    UPDATE ARDUKEY
    SET enabled = 1
    ''', [
])
connection.commit()
