#-*- coding: utf-8 -*-
#
# Fork of Tornado Database using Postgres and Mysql


# Python Imports
import logging
import threading
import time

# Extern Imports
from tornado.options import options
import psycopg2

# Project Imports
import aegis.stdlib


# These are here for mapping errors from psycopg2 into application namespace
OperationalError = psycopg2.OperationalError
IntegrityError = psycopg2.IntegrityError
DatabaseError = psycopg2.Error


# Thread-safe persistent database connection
dbconns = threading.local()


def db():
    if not hasattr(dbconns, 'databases'):
        dbconns.databases = {}
    if options.pg_database not in dbconns.databases:
        dbconns.databases[options.pg_database] = Connection.connect()
    return dbconns.databases[options.pg_database]


def dbnow():
    return db().get("SELECT NOW()")


class Connection(object):
    threads = {}

    def __init__(self, hostname, port, database, username=None, password=None, max_idle_time=7 * 3600):
        self.hostname = hostname
        self.port = port
        self.database = database
        self.max_idle_time = max_idle_time
        args = "port={0} dbname={1}".format(self.port, self.database)
        if hostname is not None:
            args += " host={0}".format(hostname)
        if username is not None:
            args += " user={0}".format(username)
        if password is not None:
            args += " password={0}".format(password)
        self._db = None
        self._db_args = args
        self._last_use_time = time.time()
        try:
            self.reconnect()
        except Exception:
            logging.error("Cannot connect to PostgreSQL: %s", self.hostname, exc_info=True)

    def __del__(self):
        self.close()

    def close(self):
        if getattr(self, "_db", None) is not None:
            self._db.close()
            self._db = None

    @classmethod
    def connect(cls, **kwargs):
        if 'pg_database' in kwargs:
            database = kwargs['pg_database']
            hostname = kwargs['pg_hostname']
            username = kwargs['pg_username']
            password = kwargs['pg_password']
            port = kwargs.get('pg_port', 5432)
        else:
            database = options.pg_database
            hostname = options.pg_hostname
            username = options.pg_username
            password = options.pg_password
            port = options.pg_port
        # force a new connection
        if kwargs.get('force', False):
            return cls(hostname, port, database, username, password)
        # check existing connections
        ident = threading.current_thread().ident
        connections = cls.threads.setdefault(ident, {})
        if not database in connections:
            conn = cls(hostname, port, database, username, password)
            conn.database = database
            cls.threads[ident][database] = conn
        return connections[database]

    def reconnect(self):
        self.close()
        self._db = psycopg2.connect(self._db_args)

    def query(self, query, *parameters, **kwargs):
        """ Returns a row list for the given query and parameters."""
        cursor = self._cursor()
        try:
            self._execute(cursor, query, parameters)
            column_names = [d[0] for d in cursor.description]
            cls = kwargs.get('cls')
            if cls:
                rows = [cls(list(zip(column_names, row))) for row in cursor]
                #aegis.stdlib.logw(rows, "DATA")
                return rows
            else:
                return [Row(zip(column_names, row)) for row in cursor]
        finally:
            cursor.close()

    def get(self, query, *parameters, **kwargs):
        """ Returns the first row returned for the given query."""
        rows = self.query(query, *parameters, **kwargs)
        if not rows:
            return None
        elif len(rows) > 1:
            raise Exception("Multiple rows returned for Database.get() query")
        else:
            return rows[0]

    def execute(self, query, *parameters):
        if query.startswith('INSERT'):
            return self.execute_lastrowid(query, *parameters)
        else:
            return self.execute_rowcount(query, *parameters)

    def execute_lastrowid(self, query, *parameters):
        """ Executes the given query, returning the lastrowid from the query."""
        cursor = self._cursor()
        try:
            self._execute(cursor, query, parameters)
            if cursor.rowcount > 0:
                last_row_id = cursor.fetchone()[0]
                #aegis.stdlib.logw(last_row_id, "LAST ROW ID")
                return last_row_id
        finally:
            cursor.close()

    def execute_rowcount(self, query, *parameters):
        """ Return the rowcount from the query."""
        cursor = self._cursor()
        try:
            self._execute(cursor, query, parameters)
            return cursor.rowcount
        finally:
            cursor.close()

    def executemany(self, query, parameters):
        """ Return the lastrowid from the query."""
        return self.executemany_lastrowid(query, parameters)

    def executemany_lastrowid(self, query, parameters):
        """ Return the lastrowid from the query."""
        cursor = self._cursor()
        try:
            cursor.executemany(query, parameters)
            return cursor.lastrowid
        finally:
            cursor.close()

    def executemany_rowcount(self, query, parameters):
        """ Return the rowcount from the query."""
        cursor = self._cursor()
        try:
            cursor.executemany(query, parameters)
            return cursor.rowcount
        finally:
            cursor.close()

    def _ensure_connected(self):
        """ If connection is open for more than max_idle_time, close and reconnect """
        if (self._db is None or (time.time() - self._last_use_time > self.max_idle_time)):
            self.reconnect()
        self._last_use_time = time.time()

    def _cursor(self):
        self._ensure_connected()
        return self._db.cursor()

    def _execute(self, cursor, query, parameters):
        try:
            # return cursor.execute(query, parameters)
            cursor.execute(query, parameters)
            return self._db.commit()
        except OperationalError:
            logging.error("Error connecting to PostgreSQL")
            self.close()
            raise
        except DatabaseError:
            logging.error("General Error at PostgreSQL - rollback transaction and carry on!")
            self.rollback()
            raise

    def rollback(self):
        if getattr(self, "_db", None) is not None:
            self._db.rollback()


# To support inserting something literally, like NOW(), into mini-ORM below
class Literal(str):
    pass


class Row(dict):
    @classmethod
    def logw(cls, msg, value, row_id):
        logging.warning("%s: %s %s", msg, value, row_id)

    @classmethod
    def scan_id(cls, column, row_id):
        sql = 'SELECT * FROM %s WHERE %s=%%s' % (cls.table_name, column)
        return db().query(sql, row_id, cls=cls)

    @classmethod
    def map_items(cls, items, key):
        return cls([(item[key], item) for item in items])

    @classmethod
    def map_id(cls, row_id, where_col, key_col, debug=False):
        items = cls.map_items(cls.scan_id(where_col, row_id), key_col)
        if debug:
            cls.logw("WHERE", where_col, row_id)
            logging.warning("")
            cls.logw("SCAN", cls.scan_id(where_col, row_id), row_id)
            logging.warning("")
            cls.logw("ITEMS", items, row_id)
        return items

    @classmethod
    def get_id(cls, column_id_val, member_id=None):
        sql = 'SELECT * FROM %s WHERE %s=%%s'
        args = [int(column_id_val)]
        if member_id:
            sql = sql + ' AND member_id=%%s'
            args.append(int(member_id))
        sql = sql % (cls.table_name, cls.id_column)
        val = db().get(sql, *args, cls=cls)
        return val

    # kva_split(), insert(), update() together are a mini-ORM in processing arbitrary column-value combinations on a row.
    # define table_name and data_columns to know which are allowed to be set along with user action
    # columns and where are simple dictionaries: {'full_name': "FULL NAME", 'email': 'email@example.com'}
    @staticmethod
    def kva_split(columns):
        keys = []
        values = []
        args = []
        for key, value in columns.items():
            keys.append('%s' % key)
            if isinstance(value, Literal):
                values.append(value)
            else:
                values.append('%s')
                args.append(value)
        return keys, values, args

    @classmethod
    def insert_columns(cls, sql_txt='INSERT INTO %(db_table)s (%(keys)s) VALUES (%(values)s)', **columns):
        db_table = cls.table_name
        keys, values, args = cls.kva_split(columns)
        sql_txt += " RETURNING " + cls.id_column
        sql = sql_txt % {'db_table': db_table, 'keys': ', '.join(keys), 'values': ', '.join(values)}
        #aegis.stdlib.logw(sql, "SQL")
        #aegis.stdlib.logw(args, "ARGS")
        return db().execute(sql, *args)

    @classmethod
    def update_columns(cls, columns, where):
        if not columns:
            logging.debug('Nothing to update. Skipping query')
            return
        db_table = cls.table_name
        # SET clause
        keys, values, args = cls.kva_split(columns)
        set_clause = ', '.join(['%s=%s' % (key, value) for key, value in zip(keys, values)])
        # WHERE clause
        keys, values, args2 = cls.kva_split(where)
        args += args2
        where_clause = ' AND '.join(['%s=%s' % (key, value) for key, value in zip(keys, values)])
        # SQL statement
        sql = 'UPDATE %s SET %s WHERE %s' % (db_table, set_clause, where_clause)
        return db().execute_rowcount(sql, *args)

    """ A dict that allows for object-like property access syntax."""
    def __getattr__(self, name):
        try:
            return self[name]
        except KeyError:
            raise AttributeError(name)


class SqlDiff(Row):
    table_name = 'sql_diff'
    id_column = 'sql_diff_id'

    @staticmethod
    def create_table():
        sql_diff_table = """
            CREATE TABLE IF NOT EXISTS
            sql_diff (
              sql_diff_id SERIAL NOT NULL,
              sql_diff_name VARCHAR(80) NOT NULL,
              create_dttm TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
              applied_dttm TIMESTAMP DEFAULT NULL,
              PRIMARY KEY (sql_diff_name)
            )"""
        return db().execute(sql_diff_table)

    @staticmethod
    def insert(sql_diff_name):
        sql = 'INSERT INTO sql_diff (sql_diff_name) VALUES (%s) RETURNING sql_diff_id'
        return db().execute(sql, sql_diff_name)

    @classmethod
    def scan(cls):
        sql = 'SELECT * FROM sql_diff'
        return db().query(sql, cls=cls)

    @staticmethod
    def mark_applied(sql_diff_name):
        sql = 'UPDATE sql_diff SET applied_dttm=NOW() WHERE sql_diff_name=%s'
        return db().execute(sql, sql_diff_name)

    @classmethod
    def scan_unapplied(cls):
        sql = """SELECT * FROM sql_diff WHERE applied_dttm IS NULL ORDER BY SUBSTRING(sql_diff_name from 5 for 3) ASC"""
        return db().query(sql, cls=cls)
