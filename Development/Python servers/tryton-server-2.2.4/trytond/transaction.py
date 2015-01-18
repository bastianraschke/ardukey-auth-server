#This file is part of Tryton.  The COPYRIGHT file at the top level of
#this repository contains the full copyright notices and license terms.
from threading import local
from trytond.tools.singleton import Singleton
from trytond.backend import Database


class _TransactionManager(object):
    '''
    Manage transaction start/stop
    '''

    def __enter__(self):
        return Transaction()

    def __exit__(self, type, value, traceback):
        Transaction().stop()


class _AttributeManager(object):
    '''
    Manage Attribute of transaction
    '''

    def __init__(self, **kwargs):
        self.kwargs = kwargs

    def __enter__(self):
        return Transaction()

    def __exit__(self, type, value, traceback):
        for name, value in self.kwargs.iteritems():
            setattr(Transaction(), name, value)


class _CursorManager(object):
    '''
    Manage cursor of transaction
    '''

    def __init__(self, cursor):
        self.cursor = cursor

    def __enter__(self):
        return Transaction()

    def __exit__(self, type, value, traceback):
        Transaction().cursor.close()
        Transaction().cursor = self.cursor


class Transaction(local):
    '''
    Control the transaction
    '''
    __metaclass__ = Singleton

    cursor = None
    user = None
    context = None
    create_records = None
    delete_records = None
    delete = None # TODO check to merge with delete_records
    timestamp = None

    def start(self, database_name, user, readonly=False, context=None):
        '''
        Start transaction
        '''
        assert self.user is None
        assert self.cursor is None
        assert self.context is None
        self.user = user
        database = Database(database_name).connect()
        self.cursor = database.cursor(readonly=readonly)
        self.context = context or {}
        self.create_records = {}
        self.delete_records = {}
        self.delete = {}
        self.timestamp = {}
        return _TransactionManager()

    def stop(self):
        '''
        Stop transaction
        '''
        self.cursor.close()
        self.cursor = None
        self.user = None
        self.context = None
        self.create_records = None
        self.delete_records = None
        self.delete = None
        self.timestamp = None

    def set_context(self, context=None, **kwargs):
        if context is None:
            context = {}
        manager = _AttributeManager(context=self.context.copy())
        self.context.update(context)
        if kwargs:
            self.context.update(kwargs)
        return manager

    def reset_context(self):
        manager = _AttributeManager(context=self.context)
        self.context = {}
        return manager

    def set_user(self, user, set_context=False):
        manager = _AttributeManager(user=self.user,
                context=self.context.copy())
        if set_context:
            self.context.update({'user': self.user})
        self.user = user
        return manager

    def set_cursor(self, cursor):
        manager = _AttributeManager(cursor=self.cursor)
        self.cursor = cursor
        return manager

    def new_cursor(self):
        manager = _CursorManager(self.cursor)
        database = Database(self.cursor.database_name).connect()
        self.cursor = database.cursor()
        return manager

    @property
    def language(self):
        if self.context:
            return self.context.get('language') or 'en_US'
        return 'en_US'
