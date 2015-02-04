#!/usr/bin/env python
# -*- coding: utf-8 -*-
#This file is part of Tryton.  The COPYRIGHT file at the top level of
#this repository contains the full copyright notices and license terms.
import unittest
import datetime
from trytond.tests.test_tryton import POOL, DB_NAME, USER, CONTEXT, \
        install_module
from trytond.transaction import Transaction


class SequenceTestCase(unittest.TestCase):
    '''
    Test Sequence
    '''

    def setUp(self):
        install_module('test')
        self.sequence = POOL.get('ir.sequence')

    def test0010incremental(self):
        '''
        Test incremental
        '''
        with Transaction().start(DB_NAME, USER,
                context=CONTEXT) as transaction:
            sequence_id = self.sequence.create({
                'name': 'Test incremental',
                'code': 'test',
                'prefix': '',
                'suffix': '',
                'type': 'incremental',
                })
            self.assertEqual(self.sequence.get_id(sequence_id), '1')

            self.sequence.write(sequence_id, {
                'number_increment': 10,
                })
            self.assertEqual(self.sequence.get_id(sequence_id), '2')
            self.assertEqual(self.sequence.get_id(sequence_id), '12')

            self.sequence.write(sequence_id, {
                'padding': 3,
                })
            self.assertEqual(self.sequence.get_id(sequence_id), '022')

            transaction.cursor.rollback()

    def test0020decimal_timestamp(self):
        '''
        Test Decimal Timestamp
        '''
        with Transaction().start(DB_NAME, USER,
                context=CONTEXT) as transaction:
            sequence_id = self.sequence.create({
                'name': 'Test decimal timestamp',
                'code': 'test',
                'prefix': '',
                'suffix': '',
                'type': 'decimal timestamp',
                })
            timestamp = self.sequence.get_id(sequence_id)
            sequence = self.sequence.read(sequence_id, ['last_timestamp'])
            self.assertEqual(timestamp, str(sequence['last_timestamp']))

            self.assertNotEqual(self.sequence.get_id(sequence_id), timestamp)

            sequence = self.sequence.browse(sequence_id)
            next_timestamp = self.sequence._timestamp(sequence)
            self.assertRaises(Exception, self.sequence.write, sequence_id, {
                'last_timestamp': next_timestamp + 100,
                })

            transaction.cursor.rollback()

    def test0030hexadecimal_timestamp(self):
        '''
        Test Hexadecimal Timestamp
        '''
        with Transaction().start(DB_NAME, USER,
                context=CONTEXT) as transaction:
            sequence_id = self.sequence.create({
                'name': 'Test hexadecimal timestamp',
                'code': 'test',
                'prefix': '',
                'suffix': '',
                'type': 'hexadecimal timestamp',
                })
            timestamp = self.sequence.get_id(sequence_id)
            sequence = self.sequence.read(sequence_id, ['last_timestamp'])
            self.assertEqual(timestamp,
                    hex(int(sequence['last_timestamp']))[2:].upper())

            self.assertNotEqual(self.sequence.get_id(sequence_id), timestamp)

            sequence = self.sequence.browse(sequence_id)
            next_timestamp = self.sequence._timestamp(sequence)
            self.assertRaises(Exception, self.sequence.write, sequence_id, {
                'last_timestamp': next_timestamp + 100,
                })

            transaction.cursor.rollback()

    def test0040prefix_suffix(self):
        '''
        Test prefix/suffix
        '''
        with Transaction().start(DB_NAME, USER, context=CONTEXT):
            sequence_id = self.sequence.create({
                'name': 'Test incremental',
                'code': 'test',
                'prefix': 'prefix/',
                'suffix': '/suffix',
                'type': 'incremental',
                })
            self.assertEqual(self.sequence.get_id(sequence_id),
                    'prefix/1/suffix')

            self.sequence.write(sequence_id, {
                'prefix': '${year}-${month}-${day}/',
                'suffix': '/${day}.${month}.${year}',
                })
            context = CONTEXT.copy()
            with Transaction().set_context(date=datetime.date(2010, 8, 15)):
                self.assertEqual(self.sequence.get_id(sequence_id),
                        '2010-08-15/2/15.08.2010')

def suite():
    return unittest.TestLoader().loadTestsFromTestCase(SequenceTestCase)

if __name__ == '__main__':
    suite = suite()
    unittest.TextTestRunner(verbosity=2).run(suite)
