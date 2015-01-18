#This file is part of Tryton.  The COPYRIGHT file at the top level of
#this repository contains the full copyright notices and license terms.
from trytond.backend.database import DatabaseInterface, CursorInterface
from trytond.config import CONFIG
from trytond.session import Session
from psycopg2.pool import ThreadedConnectionPool
from psycopg2.extensions import cursor as PsycopgCursor
from psycopg2.extensions import ISOLATION_LEVEL_REPEATABLE_READ
from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT
from psycopg2.extensions import register_type, register_adapter
from psycopg2.extensions import UNICODE, AsIs
try:
    from psycopg2.extensions import PYDATE, PYDATETIME, PYTIME
except ImportError:
    PYDATE, PYDATETIME, PYTIME = None, None, None
from psycopg2 import IntegrityError as DatabaseIntegrityError
from psycopg2 import OperationalError as DatabaseOperationalError
import time
import logging
import re
import os
if os.name == 'posix':
    import pwd
from decimal import Decimal
from trytond.protocols.datatype import Float

RE_FROM = re.compile('.* from "?([a-zA-Z_0-9]+)"?.*$')
RE_INTO = re.compile('.* into "?([a-zA-Z_0-9]+)"?.*$')
RE_VERSION = re.compile(r'\S+ (\d+)\.(\d+)')


class Database(DatabaseInterface):

    _databases = {}
    _connpool = None
    _list_cache = None
    _list_cache_timestamp = None
    _version_cache = {}

    def __new__(cls, database_name='template1'):
        if database_name in cls._databases:
            return cls._databases[database_name]
        return DatabaseInterface.__new__(cls, database_name=database_name)

    def __init__(self, database_name='template1'):
        super(Database, self).__init__(database_name=database_name)
        self._databases.setdefault(database_name, self)

    def connect(self):
        if self._connpool is not None:
            return self
        logger = logging.getLogger('database')
        logger.info('connect to "%s"' % self.database_name)
        host = CONFIG['db_host'] and "host=%s" % CONFIG['db_host'] or ''
        port = CONFIG['db_port'] and "port=%s" % CONFIG['db_port'] or ''
        name = "dbname=%s" % self.database_name
        user = CONFIG['db_user'] and "user=%s" % CONFIG['db_user'] or ''
        password = CONFIG['db_password'] \
                and "password=%s" % CONFIG['db_password'] or ''
        minconn = int(CONFIG['db_minconn']) or 1
        maxconn = int(CONFIG['db_maxconn']) or 64
        dsn = '%s %s %s %s %s' % (host, port, name, user, password)
        self._connpool = ThreadedConnectionPool(minconn, maxconn, dsn)
        return self

    def cursor(self, autocommit=False, readonly=False):
        if self._connpool is None:
            self.connect()
        conn = self._connpool.getconn()
        if autocommit:
            conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
        else:
            conn.set_isolation_level(ISOLATION_LEVEL_REPEATABLE_READ)
        cursor = Cursor(self._connpool, conn, self)
        # TODO change for set_session
        if readonly:
            cursor.execute('SET TRANSACTION READ ONLY')
        return cursor

    def close(self):
        if self._connpool is None:
            return
        self._connpool.closeall()
        self._connpool = None

    def create(self, cursor, database_name):
        cursor.execute('CREATE DATABASE "' + database_name + '" ' \
                'TEMPLATE template0 ENCODING \'unicode\'')
        Database._list_cache = None

    def drop(self, cursor, database_name):
        cursor.execute('DROP DATABASE "' + database_name + '"')
        Database._list_cache = None

    def get_version(self, cursor):
        if self.database_name not in self._version_cache:
            cursor.execute('SELECT version()')
            version, = cursor.fetchone()
            self._version_cache[self.database_name] = tuple(map(int,
                RE_VERSION.search(version).groups()))
        return self._version_cache[self.database_name]

    @staticmethod
    def dump(database_name):
        from trytond.tools import exec_pg_command_pipe

        cmd = ['pg_dump', '--format=c', '--no-owner']
        if CONFIG['db_user']:
            cmd.append('--username=' + CONFIG['db_user'])
        if CONFIG['db_host']:
            cmd.append('--host=' + CONFIG['db_host'])
        if CONFIG['db_port']:
            cmd.append('--port=' + CONFIG['db_port'])
        cmd.append(database_name)

        pipe = exec_pg_command_pipe(*tuple(cmd))
        pipe.stdin.close()
        data = pipe.stdout.read()
        res = pipe.wait()
        if res:
            raise Exception('Couldn\'t dump database!')
        return data

    @staticmethod
    def restore(database_name, data):
        from trytond.tools import exec_pg_command_pipe

        database = Database().connect()
        cursor = database.cursor(autocommit=True)
        database.create(cursor, database_name)
        cursor.commit()
        cursor.close()

        cmd = ['pg_restore', '--no-owner']
        if CONFIG['db_user']:
            cmd.append('--username=' + CONFIG['db_user'])
        if CONFIG['db_host']:
            cmd.append('--host=' + CONFIG['db_host'])
        if CONFIG['db_port']:
            cmd.append('--port=' + CONFIG['db_port'])
        cmd.append('--dbname=' + database_name)
        args2 = tuple(cmd)

        if os.name == "nt":
            tmpfile = (os.environ['TMP'] or 'C:\\') + os.tmpnam()
            with open(tmpfile, 'wb') as fp:
                fp.write(data)
            args2 = list(args2)
            args2.append(' ' + tmpfile)
            args2 = tuple(args2)

        pipe = exec_pg_command_pipe(*args2)
        if not os.name == "nt":
            pipe.stdin.write(data)
        pipe.stdin.close()
        res = pipe.wait()
        if res:
            raise Exception('Couldn\'t restore database')

        database = Database(database_name).connect()
        cursor = database.cursor()
        if not cursor.test():
            cursor.close()
            database.close()
            raise Exception('Couldn\'t restore database!')
        cursor.close()
        database.close()
        Database._list_cache = None
        return True

    @staticmethod
    def list(cursor):
        now = time.time()
        timeout = int(CONFIG['session_timeout'])
        res = Database._list_cache
        if res and abs(Database._list_cache_timestamp - now) < timeout:
            return res
        db_user = CONFIG['db_user']
        if not db_user and os.name == 'posix':
            db_user = pwd.getpwuid(os.getuid())[0]
        if not db_user:
            cursor.execute("SELECT usename " \
                    "FROM pg_user " \
                    "WHERE usesysid = (" \
                        "SELECT datdba " \
                        "FROM pg_database " \
                        "WHERE datname = %s)",
                        (CONFIG["db_name"],))
            res = cursor.fetchone()
            db_user = res and res[0]
        if db_user:
            cursor.execute("SELECT datname " \
                    "FROM pg_database " \
                    "WHERE datdba = (" \
                        "SELECT usesysid " \
                        "FROM pg_user " \
                        "WHERE usename=%s) " \
                        "AND datname not in " \
                            "('template0', 'template1', 'postgres') " \
                    "ORDER BY datname",
                            (db_user,))
        else:
            cursor.execute("SELECT datname " \
                    "FROM pg_database " \
                    "WHERE datname not in " \
                        "('template0', 'template1','postgres') " \
                    "ORDER BY datname")
        res = []
        for db_name, in cursor.fetchall():
            db_name = db_name.encode('utf-8')
            try:
                database = Database(db_name).connect()
            except Exception:
                continue
            cursor2 = database.cursor()
            if cursor2.test():
                res.append(db_name)
                cursor2.close(close=True)
            else:
                cursor2.close(close=True)
                database.close()
        Database._list_cache = res
        Database._list_cache_timestamp = now
        return res

    @staticmethod
    def init(cursor):
        from trytond.tools import safe_eval
        sql_file = os.path.join(os.path.dirname(__file__), 'init.sql')
        with open(sql_file) as fp:
            for line in fp.read().split(';'):
                if (len(line)>0) and (not line.isspace()):
                    cursor.execute(line)

        for i in ('ir', 'workflow', 'res', 'webdav'):
            root_path = os.path.join(os.path.dirname(__file__), '..', '..')
            tryton_file = os.path.join(root_path, i, '__tryton__.py')
            mod_path = os.path.join(root_path, i)
            with open(tryton_file) as fp:
                info = safe_eval(fp.read())
            active = info.get('active', False)
            if active:
                state = 'to install'
            else:
                state = 'uninstalled'
            cursor.execute('SELECT NEXTVAL(\'ir_module_module_id_seq\')')
            module_id = cursor.fetchone()[0]
            cursor.execute('INSERT INTO ir_module_module ' \
                    '(id, create_uid, create_date, author, website, name, ' \
                    'shortdesc, description, state) ' \
                    'VALUES (%s, %s, now(), %s, %s, %s, %s, %s, %s)',
                    (module_id, 0, info.get('author', ''),
                info.get('website', ''), i, info.get('name', False),
                info.get('description', ''), state))
            dependencies = info.get('depends', [])
            for dependency in dependencies:
                cursor.execute('INSERT INTO ir_module_module_dependency ' \
                        '(create_uid, create_date, module, name) ' \
                        'VALUES (%s, now(), %s, %s)',
                        (0, module_id, dependency))


class _Cursor(PsycopgCursor):

    def __build_dict(self, row):
        return dict((desc[0], row[i])
                for i, desc in enumerate(self.description))

    def dictfetchone(self):
        row = self.fetchone()
        if row:
            return self.__build_dict(row)
        else:
            return row

    def dictfetchmany(self, size):
        rows = self.fetchmany(size)
        return [self.__build_dict(row) for row in rows]

    def dictfetchall(self):
        rows = self.fetchall()
        return [self.__build_dict(row) for row in rows]


class Cursor(CursorInterface):

    def __init__(self, connpool, conn, database):
        super(Cursor, self).__init__()
        self._connpool = connpool
        self._conn = conn
        self._database = database
        self.cursor = conn.cursor(cursor_factory=_Cursor)
        self.commit()
        self.sql_from_log = {}
        self.sql_into_log = {}
        self.count = {
            'from': 0,
            'into': 0,
        }

    @property
    def database_name(self):
        return self._database.database_name

    # TODO to remove
    @property
    def dbname(self):
        return self.database_name

    def __getattr__(self, name):
        return getattr(self.cursor, name)

    def execute(self, sql, params=None):
        if self.sql_log:
            now = time.time()

        try:
            if params:
                res = self.cursor.execute(sql, params)
            else:
                res = self.cursor.execute(sql)
        except Exception:
            logger = logging.getLogger('sql')
            logger.error('Wrong SQL: ' + (self.cursor.query or ''))
            raise
        if self.sql_log:
            res_from = RE_FROM.match(sql.lower())
            if res_from:
                self.sql_from_log.setdefault(res_from.group(1), [0, 0])
                self.sql_from_log[res_from.group(1)][0] += 1
                self.sql_from_log[res_from.group(1)][1] += time.time() - now
                self.count['from'] += 1
            res_into = RE_INTO.match(sql.lower())
            if res_into:
                self.sql_into_log.setdefault(res_into.group(1), [0, 0])
                self.sql_into_log[res_into.group(1)][0] += 1
                self.sql_into_log[res_into.group(1)][1] += time.time() - now
                self.count['into'] += 1
        return res

    def _print_log(self, sql_type='from'):
        logger = logging.getLogger('sql')
        logger.info("SQL LOG %s:" % (sql_type,))
        if sql_type == 'from':
            logs = self.sql_from_log.items()
        else:
            logs = self.sql_into_log.items()
        logs.sort(lambda x, y: cmp(x[1][1], y[1][1]))
        amount = 0
        for log in logs:
            logger.info("table:%s:%f/%d" % (log[0], log[1][1], log[1][0]))
            amount += log[1][1]
        logger.info("SUM:%s/%d" % (amount, self.count[sql_type]))

    def close(self, close=False):
        if self.sql_log:
            self._print_log('from')
            self._print_log('into')
        self.cursor.close()

        # This force the cursor to be freed, and thus, available again. It is
        # important because otherwise we can overload the server very easily
        # because of a cursor shortage (because cursors are not garbage
        # collected as fast as they should). The problem is probably due in
        # part because browse records keep a reference to the cursor.
        del self.cursor
        #if id(self._conn) in self._connpool._rused:
        self.rollback()
        self._connpool.putconn(self._conn, close=close)

    def commit(self):
        super(Cursor, self).commit()
        self._conn.commit()

    def rollback(self):
        super(Cursor, self).rollback()
        self._conn.rollback()

    def test(self):
        self.cursor.execute("SELECT relname " \
                "FROM pg_class " \
                "WHERE relkind = 'r' AND relname in (" \
                "'ir_model', "
                "'ir_model_field', "
                "'ir_ui_view', "
                "'ir_ui_menu', "
                "'res_user', "
                "'res_group', "
                "'wkf', "
                "'wkf_activity', "
                "'wkf_transition', "
                "'wkf_instance', "
                "'wkf_workitem', "
                "'wkf_witm_trans', "
                "'ir_module_module', "
                "'ir_module_module_dependency', "
                "'ir_translation', "
                "'ir_lang'"
                ")")
        return len(self.cursor.fetchall()) != 0

    def nextid(self, table):
        self.cursor.execute("SELECT NEXTVAL('" + table + "_id_seq')")
        return self.cursor.fetchone()[0]

    def setnextid(self, table, value):
        self.cursor.execute("SELECT SETVAL('" + table + "_id_seq', %d)" % value)

    def currid(self, table):
        self.cursor.execute('SELECT last_value FROM "' + table + '_id_seq"')
        return self.cursor.fetchone()[0]

    def lock(self, table):
        self.cursor.execute('LOCK "%s"' % table)

    def has_constraint(self):
        return True

    def limit_clause(self, select, limit=None, offset=None):
        if limit is not None:
            select += ' LIMIT %d' % limit
        if offset is not None and offset != 0:
            select += ' OFFSET %d' % offset
        return select

    def has_returning(self):
        # RETURNING clause is available since PostgreSQL 8.2
        return self._database.get_version(self) >= (8, 2)

register_type(UNICODE)
if PYDATE:
    register_type(PYDATE)
if PYDATETIME:
    register_type(PYDATETIME)
if PYTIME:
    register_type(PYTIME)
register_adapter(Session, AsIs)
register_adapter(float, lambda value: AsIs(repr(value)))
register_adapter(Float, lambda value: AsIs(repr(value)))
register_adapter(Decimal, lambda value: AsIs(str(value)))
