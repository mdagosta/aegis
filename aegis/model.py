#-*- coding: utf-8 -*-
#
# Core common Data Model that will applies to a lot of applications


# Python Imports
import datetime
import hashlib
import json
import logging
import random
import uuid

# Project Imports
import aegis.stdlib
import aegis.database
import aegis.config

db = aegis.database.db


class SqlDiff(aegis.database.Row):
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
        sql = 'INSERT INTO sql_diff (sql_diff_name) VALUES (%s)'
        if type(db()) is aegis.database.PostgresConnection:
            sql += ' RETURNING sql_diff_id'
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


class UserAgent(aegis.database.Row):
    table_name = 'user_agent'
    id_column = 'user_agent_id'

    @staticmethod
    def insert(user_agent_tx, dbconn=None):
        dbconn = dbconn if dbconn else db()
        user_agent_md5 = hashlib.md5(str(user_agent_tx).encode('utf-8')).hexdigest()
        sql = 'INSERT INTO user_agent (user_agent_tx, user_agent_md5) VALUES (%s, %s)'
        if type(dbconn) is aegis.database.PostgresConnection:
            sql += ' RETURNING user_agent_id'
        return dbconn.execute(sql, user_agent_tx, user_agent_md5)

    @classmethod
    def get_agent(cls, user_agent_tx, dbconn=None):
        dbconn = dbconn if dbconn else db()
        user_agent_md5 = hashlib.md5(str(user_agent_tx).encode('utf-8')).hexdigest()
        sql = 'SELECT * FROM user_agent WHERE user_agent_md5=%s'
        return dbconn.get(sql, user_agent_md5, cls=cls)

    @classmethod
    def set_user_agent(cls, user_agent_tx, dbconn=None):
        user_agent_row = cls.get_agent(user_agent_tx, dbconn=dbconn)
        if not user_agent_row:
            try:
                user_agent_id = cls.insert(user_agent_tx, dbconn=dbconn)
                user_agent_row = cls.get_id(user_agent_id, dbconn=dbconn)
            except (aegis.database.PgsqlIntegrityError, aegis.database.MysqlIntegrityError) as ex:
                user_agent_row = cls.get_agent(user_agent_tx, dbconn=dbconn)
                if not user_agent_row:
                    logging.exception(ex)
        return user_agent_row

    @staticmethod
    def set_robot_user_id(user_agent_id, robot_user_id, dbconn=None):
        dbconn = dbconn if dbconn else db()
        sql = 'UPDATE user_agent SET robot_user_id=%s WHERE user_agent_id=%s'
        return dbconn.execute(sql, robot_user_id, user_agent_id)

    @staticmethod
    def set_robot_ind(user_agent_id, robot_ind, dbconn=None):
        dbconn = dbconn if dbconn else db()
        user_agent_id = int(user_agent_id)
        robot_ind = bool(robot_ind)
        if robot_ind not in [True, False]:
            return False
        sql = 'UPDATE user_agent SET robot_ind=%s WHERE user_agent_id=%s'
        return dbconn.execute(sql, robot_ind, user_agent_id)

    def set_ua_json(self, ua_json, dbconn=None):
        dbconn = dbconn if dbconn else db()
        if self['user_agent_json'] or not ua_json:
            return
        sql = "UPDATE user_agent SET user_agent_json=%s WHERE user_agent_id=%s"
        return dbconn.execute(sql, ua_json, self['user_agent_id'])


class User(aegis.database.Row):
    table_name = 'user_' if aegis.database.pgsql_available else 'user'
    table_names = {'pgsql': 'user_', 'mysql': 'user'}
    id_column = 'user_id'

    @classmethod
    def insert(cls, user_agent_id, dbconn=None):
        dbconn = dbconn if dbconn else db()
        sql = 'INSERT INTO '+cls.table_name+' (user_agent_id) VALUES (%s)'
        if type(dbconn) is aegis.database.PostgresConnection:
            sql += ' RETURNING user_id'
        return dbconn.execute(sql, user_agent_id)

    def set_member_id(self, member_id, dbconn=None):
        dbconn = dbconn if dbconn else db()
        sql = 'UPDATE '+self.table_name+' SET member_id=%s WHERE user_id=%s'
        return dbconn.execute(sql, member_id, self['user_id'])

    def set_preferences(self, preferences, dbconn=None):
        dbconn = dbconn if dbconn else db()
        preferences = json.dumps(preferences, cls=aegis.stdlib.DateTimeEncoder)
        sql = "UPDATE "+self.table_name+" SET preferences=%s WHERE user_id=%s"
        return dbconn.execute(sql, preferences, self['user_id'])


class Email(aegis.database.Row):
    table_name = 'email'
    id_column = 'email_id'

    @staticmethod
    def insert(email, dbconn=None):
        dbconn = dbconn if dbconn else db()
        sql = "INSERT INTO email (email) VALUES (%s)"
        if type(dbconn) is aegis.database.PostgresConnection:
            sql += ' RETURNING email_id'
        return dbconn.execute(sql, email)

    @classmethod
    def set_email(cls, email, dbconn=None):
        email_row = cls.get_email(email, dbconn=dbconn)
        if not email_row:
            try:
                email_id = cls.insert(email, dbconn=dbconn)
                email_row = cls.get_id(email_id, dbconn=dbconn)
            except (aegis.database.PgsqlUniqueViolation, aegis.database.MysqlIntegrityError) as ex:
                logging.error("Duplicate Key Error   aegis.model.Email.set_email(%s). Very unlikely. Read from DB and carry one.", email)
                email_row = cls.get_email(email, dbconn=dbconn)
        return email_row

    @classmethod
    def get_email(cls, email, dbconn=None):
        dbconn = dbconn if dbconn else db()
        sql = "SELECT * FROM email WHERE email=%s"
        return dbconn.get(sql, email, cls=cls)

    @classmethod
    def get_member_id(cls, member_id, dbconn=None):
        dbconn = dbconn if dbconn else db()
        sql = "SELECT * FROM email WHERE member_id=%s"
        return dbconn.get(sql, member_id, cls=cls)

    def set_member_id(self, member_id, dbconn=None):
        dbconn = dbconn if dbconn else db()
        sql = "UPDATE email SET member_id=%s WHERE email_id=%s"
        return dbconn.execute(sql, member_id, self['email_id'])

    def set_google_user_id(self, google_user_id, dbconn=None):
        dbconn = dbconn if dbconn else db()
        sql = "UPDATE email SET google_user_id=%s WHERE email_id=%s"
        return dbconn.execute(sql, google_user_id, self['email_id'])

    def deidentify(self, email_addr, dbconn=None):
        dbconn = dbconn if dbconn else db()
        # overwrite email with email_addr, stop referencing google_user.google_user_id, and mark deleted
        sql = "UPDATE email SET email=%s, google_user_id=NULL, delete_dttm=NOW() WHERE email_id=%s"
        return dbconn.execute(sql, email_addr, self['email_id'])

    def mark_verified(self, dbconn=None):
        dbconn = dbconn if dbconn else db()
        sql = "UPDATE email SET verify_dttm=NOW() WHERE email_id=%s AND verify_dttm IS NULL"
        return dbconn.execute(sql, self['email_id'])


class Member(aegis.database.Row):
    table_name = 'member'
    id_column = 'member_id'

    @staticmethod
    def insert(email_id, dbconn=None):
        dbconn = dbconn if dbconn else db()
        sql = "INSERT INTO member (email_id) VALUES (%s)"
        if type(dbconn) is aegis.database.PostgresConnection:
            sql += ' RETURNING member_id'
        return dbconn.execute(sql, email_id)

    @classmethod
    def set_member(cls, email_id, marketing_id=None, dbconn=None, **kwargs):
        member = cls.get_email_id(email_id, dbconn=dbconn)
        if not member:
            columns = {'email_id': email_id}
            columns.update(kwargs)
            if marketing_id:
                columns['marketing_id'] = marketing_id
            member_id = cls.insert_columns(dbconn=dbconn, **columns)
            member = cls.get_id(member_id, dbconn=dbconn)
        return member

    @classmethod
    def get_email_id(cls, email_id, dbconn=None):
        dbconn = dbconn if dbconn else db()
        sql = "SELECT * FROM member WHERE email_id = %s"
        return dbconn.get(sql, email_id, cls=cls)

    def set_google_user_id(self, google_user_id, dbconn=None):
        dbconn = dbconn if dbconn else db()
        sql = "UPDATE member SET google_user_id=%s WHERE member_id=%s"
        return dbconn.execute(sql, google_user_id, self['member_id'])

    @classmethod
    def get_auth(cls, member_id, dbconn=None):
        dbconn = dbconn if dbconn else db()
        if not member_id:
            return None
        member = cls.get_id(member_id, dbconn=dbconn)
        if not member:
            return None
        if member.get('email_id'):
            email = Email.get_id(member['email_id'], dbconn=dbconn)
            if email:
                member['email'] = email
        if member.get('google_user_id'):
            member['google_user'] = GoogleUser.get_id(member['google_user_id'], dbconn=dbconn)
            member['picture_url'] = member['google_user']['picture_url']
        return member

    def deidentify(self, dbconn=None):
        dbconn = dbconn if dbconn else db()
        # stop referencing google_user.google_user_id, and mark deleted
        sql = "UPDATE member SET google_user_id=NULL, delete_dttm=NOW() WHERE member_id=%s"
        return dbconn.execute(sql, self['member_id'])

    def mark_verified(self, dbconn=None):
        dbconn = dbconn if dbconn else db()
        sql = "UPDATE member SET verify_dttm=NOW() WHERE member_id=%s AND verify_dttm IS NULL"
        return dbconn.execute(sql, self['member_id'])


class MemberAuth(aegis.database.Row):
    table_name = 'member_auth'
    id_column = 'member_auth_id'
    data_columns = ('member_auth_type_id', 'magic_token', 'user_id', 'email_id', 'member_id', 'ip_address', 'expire_dttm', 'register_flag', 'login_flag')

    @classmethod
    def insert(cls, **columns):
        columns['magic_token'] = aegis.stdlib.magic_token()
        # XXX TODO Do input validation here
        return cls.insert_columns(**columns)

    @classmethod
    def get_auth(cls, member_id, member_auth_id, magic_token):
        sql = """
        SELECT *
          FROM member
          JOIN member_auth USING (member_id)
         WHERE member_id=%s
           AND member_auth_id=%s
           AND magic_token=%s
           AND member.delete_dttm IS NULL
           AND member_auth.expire_dttm > NOW()
           AND member_auth.delete_dttm IS NULL"""
        return db().get(sql, member_id, member_auth_id, magic_token, cls=cls)

    @classmethod
    def scan_member(cls, member_id):
        sql = """
        SELECT *
          FROM member
          JOIN member_auth USING (member_id)
         WHERE member_id=%s
           AND member.delete_dttm IS NULL
           AND member_auth.expire_dttm > NOW()
           AND member_auth.delete_dttm IS NULL"""
        return db().query(sql, member_id, cls=cls)

    def refresh(self, auth_duration_sec):
        auth_duration_sec = aegis.stdlib.validate_int(auth_duration_sec)
        sql = "UPDATE member_auth SET expire_dttm=NOW() + INTERVAL '%s SECOND' WHERE member_auth_id=%s"
        return db().execute(sql, auth_duration_sec, self['member_auth_id'])

    def revoke(self):
        sql = "UPDATE member_auth SET delete_dttm=NOW() WHERE member_auth_id=%s"
        return db().execute(sql, self['member_auth_id'])


class MemberAuthType(aegis.database.Row):
    table_name = 'member_auth_type'
    id_column = 'member_auth_type_id'

    @classmethod
    def get_name(cls, member_auth_type_name):
        sql = "SELECT * FROM member_auth_type WHERE member_auth_type_name=%s"
        return db().get(sql, member_auth_type_name, cls=cls)


class GoogleUser(aegis.database.Row):
    table_name = 'google_user'
    id_column = 'google_user_id'

    @staticmethod
    def insert(google_id, email_id, member_id, name, picture_url, email_verified, dbconn=None):
        dbconn = dbconn if dbconn else db()
        sql = "INSERT INTO google_user (google_id, email_id, member_id, name, picture_url, email_verified) VALUES (%s, %s, %s, %s, %s, %s) RETURNING google_user_id"
        return dbconn.execute(sql, google_id, email_id, member_id, name, picture_url, email_verified)

    @classmethod
    def set_google_user(cls, google_id, email_id, member_id, name, picture_url, email_verified, dbconn=None):
        google_user = cls.get_google_id(google_id, dbconn=dbconn)
        if not google_user:
            google_user_id = cls.insert(google_id, email_id, member_id, name, picture_url, email_verified, dbconn=dbconn)
            google_user = cls.get_id(google_user_id, dbconn=dbconn)
        return google_user

    @classmethod
    def get_google_id(cls, google_id, dbconn=None):
        dbconn = dbconn if dbconn else db()
        sql = "SELECT * FROM google_user WHERE google_id=%s"
        return dbconn.get(sql, google_id, cls=cls)

    @classmethod
    def get_member_id(cls, member_id, dbconn=None):
        dbconn = dbconn if dbconn else db()
        sql = "SELECT * FROM google_user WHERE member_id=%s"
        return dbconn.get(sql, member_id, cls=cls)

    def hard_delete(self, dbconn=None):
        dbconn = dbconn if dbconn else db()
        sql = "DELETE FROM google_user WHERE google_user_id=%s"
        return dbconn.execute(sql, self['google_user_id'])

    def set_scopes(self, scopes, dbconn=None):
        dbconn = dbconn if dbconn else db()
        sql = "UPDATE google_user SET scopes=%s WHERE google_user_id=%s"
        return dbconn.execute(sql, scopes, self['google_user_id'])


class GoogleAccess(aegis.database.Row):
    table_name = 'google_access'
    id_column = 'google_access_id'
    primary_key = ('google_access_id')

    @classmethod
    def get_google_user_id(cls, google_user_id, dbconn=None):
        dbconn = dbconn if dbconn else db()
        sql = "SELECT * FROM google_access WHERE google_user_id=%s ORDER BY expire_dttm DESC LIMIT 1"
        return dbconn.get(sql, google_user_id, cls=cls)

    @classmethod
    def purge_expired(cls, dbconn=None):
        dbconn = dbconn if dbconn else db()
        sql = "DELETE FROM google_access WHERE expire_dttm < NOW()"
        return dbconn.execute(sql)

    def hard_delete(self, dbconn=None):
        dbconn = dbconn if dbconn else db()
        sql = "DELETE FROM google_access WHERE google_access_id=%s"
        return dbconn.execute(sql, self['google_access_id'])

    @classmethod
    def hard_delete_google_user(cls, google_user_id, dbconn=None):
        dbconn = dbconn if dbconn else db()
        sql = "DELETE FROM google_access WHERE google_user_id=%s"
        return dbconn.execute(sql, google_user_id)


class GooglePicture(aegis.database.Row):
    table_name = 'google_picture'
    id_column = 'google_picture_id'
    primary_key = ('google_picture_id')

    @classmethod
    def get_google_user_id(cls, google_user_id, dbconn=None):
        dbconn = dbconn if dbconn else db()
        sql = "SELECT * FROM google_picture WHERE google_user_id=%s"
        return dbconn.get(sql, google_user_id, cls=cls)

    def hard_delete(self, dbconn=None):
        dbconn = dbconn if dbconn else db()
        sql = "DELETE FROM google_picture WHERE google_picture_id=%s"
        return dbconn.execute(sql, self['google_picture_id'])

    @classmethod
    def hard_delete_google_user(cls, google_user_id, dbconn=None):
        dbconn = dbconn if dbconn else db()
        sql = "DELETE FROM google_picture WHERE google_user_id=%s"
        return dbconn.execute(sql, google_user_id)


class EmailType(aegis.database.Row):
    table_name = 'email_type'
    id_column = 'email_type_id'

    @classmethod
    def scan(cls, dbconn=None):
        dbconn = dbconn if dbconn else db()
        sql = "SELECT * FROM email_type"
        return dbconn.query(sql, cls=cls)

    @classmethod
    def get_name(cls, email_type_name, dbconn=None):
        dbconn = dbconn if dbconn else db()
        sql = "SELECT * FROM email_type WHERE email_type_name=%s"
        return dbconn.get(sql, email_type_name, cls=cls)


class EmailTracking(aegis.database.Row):
    table_name = 'email_tracking'
    id_column = 'email_tracking_id'

    @staticmethod
    def insert(email_type_id, from_email_id, to_email_id, email_data, dbconn=None):
        dbconn = dbconn if dbconn else db()
        sql = "INSERT INTO email_tracking (email_type_id, from_email_id, to_email_id, email_uuid, email_data, send_dttm) VALUES (%s, %s, %s, %s, %s, NOW())"
        if type(dbconn) is aegis.database.PostgresConnection:
            sql += ' RETURNING email_tracking_id'
        return dbconn.execute(sql, email_type_id, from_email_id, to_email_id, uuid.uuid4().hex, email_data)

    @classmethod
    def get_params(cls, email_tracking_id, email_uuid, dbconn=None):
        dbconn = dbconn if dbconn else db()
        sql = "SELECT * FROM email_tracking WHERE email_tracking_id=%s AND email_uuid=%s"
        return dbconn.get(sql, email_tracking_id, email_uuid, cls=cls)

    @classmethod
    def scan_mailer(cls, dbconn=None):
        dbconn = dbconn if dbconn else db()
        sql = "SELECT * FROM email_tracking WHERE send_dttm < NOW() AND sent_dttm IS NULL AND delete_dttm IS NULL AND claimed_dttm IS NULL"
        return dbconn.query(sql, cls=cls)

    def claim(self, dbconn=None):
        dbconn = dbconn if dbconn else db()
        sql = 'UPDATE email_tracking SET claimed_dttm=NOW() WHERE email_tracking_id=%s AND claimed_dttm IS NULL'
        return dbconn.execute(sql, self['email_tracking_id'])

    @staticmethod
    def clear_claims(minutes=1, dbconn=None):
        dbconn = dbconn if dbconn else db()
        if type(dbconn) is aegis.database.PostgresConnection:
            sql = "UPDATE email_tracking SET claimed_dttm=NULL WHERE claimed_dttm < NOW() - INTERVAL '%s MINUTE' AND sent_dttm IS NULL" % int(minutes)
        elif type(dbconn) is aegis.database.MysqlConnection:
            sql = "UPDATE email_tracking SET claimed_dttm=NULL WHERE claimed_dttm < NOW() - INTERVAL %s MINUTE AND sent_dttm IS NULL" % int(minutes)
        return dbconn.execute_rowcount(sql)

    def mark_sent(self, dbconn=None):
        dbconn = dbconn if dbconn else db()
        sql = "UPDATE email_tracking SET sent_dttm=NOW() WHERE email_tracking_id=%s AND sent_dttm IS NULL"
        return dbconn.execute(sql, self['email_tracking_id'])

    def mark_delivered(self, dbconn=None):
        dbconn = dbconn if dbconn else db()
        sql = "UPDATE email_tracking SET deliver_dttm=NOW() WHERE email_tracking_id=%s AND deliver_dttm IS NULL"
        return dbconn.execute(sql, self['email_tracking_id'])

    def mark_opened(self, dbconn=None):
        dbconn = dbconn if dbconn else db()
        sql = "UPDATE email_tracking SET open_dttm=NOW() WHERE email_tracking_id=%s AND open_dttm IS NULL"
        return dbconn.execute(sql, self['email_tracking_id'])

    def mark_clicked(self, dbconn=None):
        dbconn = dbconn if dbconn else db()
        sql = "UPDATE email_tracking SET click_dttm=NOW() WHERE email_tracking_id=%s AND click_dttm IS NULL"
        return dbconn.execute(sql, self['email_tracking_id'])

    def mark_deleted(self, dbconn=None):
        dbconn = dbconn if dbconn else db()
        sql = "UPDATE email_tracking SET delete_dttm=NOW() WHERE email_tracking_id=%s AND delete_dttm IS NULL"
        return dbconn.execute(sql, self['email_tracking_id'])


class EmailLink(aegis.database.Row):
    table_name = 'email_link'
    id_column = 'email_link_id'

    @staticmethod
    def insert(email_id):
        sql = "INSERT INTO email_link (email_id, magic_token) VALUES (%s, %s)"
        if type(db()) is aegis.database.PostgresConnection:
            sql += ' RETURNING email_link_id'
        return db().execute(sql, email_id, aegis.stdlib.magic_token())

    def mark_accessed(self):
        sql = "UPDATE email_link SET access_dttm=NOW(), delete_dttm=NOW() WHERE email_link_id=%s AND access_dttm IS NULL"
        return db().execute(sql, self['email_link_id'])

    def set_email_tracking_id(self, email_tracking_id):
        sql = "UPDATE email_link SET email_tracking_id=%s WHERE email_link_id=%s AND email_tracking_id IS NULL"
        return db().execute(sql, email_tracking_id, self['email_link_id'])

    @classmethod
    def scan_latest(cls, email_id, limit=6):
        sql = "SELECT * FROM email_tracking JOIN email_link USING (email_tracking_id) WHERE email_type_id=2 AND to_email_id=%s ORDER BY email_tracking_id DESC LIMIT %s"
        return db().query(sql, email_id, limit, cls=cls)

    @classmethod
    def get_token(cls, magic_token):
        sql = "SELECT * FROM email_link WHERE magic_token=%s"
        return db().get(sql, magic_token, cls=cls)

    @classmethod
    def get_id_token(cls, email_link_id, magic_token):
        sql = "SELECT * FROM email_link WHERE email_link_id=%s AND magic_token=%s"
        return db().get(sql, email_link_id, magic_token, cls=cls)


class Pageview(aegis.database.Row):
    table_name = 'pageview'
    id_column = 'pageview_id'

    @classmethod
    def insert(cls, user_id, member_id, url_path, url_query, url_tx, request_name):
        sql = "INSERT INTO pageview (user_id, member_id, url_path, url_query, url_tx, request_name) VALUES (%s, %s, %s, %s, %s, %s)"
        if type(db()) is aegis.database.PostgresConnection:
            sql += ' RETURNING pageview_id'
        return db().execute(sql, user_id, member_id, url_path, url_query, url_tx, request_name)


class HydraType(aegis.database.Row):
    table_name = 'hydra_type'
    id_column = 'hydra_type_id'
    data_columns = ('hydra_type_name', 'hydra_type_desc', 'priority_ndx', 'next_run_sql', 'claimed_dttm', 'run_host', 'run_env')

    @classmethod
    def get_name(cls, hydra_type_name, dbconn=None):
        dbconn = dbconn if dbconn else db()
        sql = "SELECT * FROM hydra_type WHERE hydra_type_name=%s"
        return dbconn.get(sql, hydra_type_name, cls=cls)

    @classmethod
    def scan(cls, dbconn=None):
        dbconn = dbconn if dbconn else db()
        sql = "SELECT * FROM hydra_type ORDER BY next_run_dttm ASC, status ASC, priority_ndx ASC"
        return dbconn.query(sql, cls=cls)

    def run_now(self, dbconn=None):
        dbconn = dbconn if dbconn else db()
        sql = "UPDATE hydra_type SET next_run_dttm=NOW(), status='live', claimed_dttm=NULL WHERE hydra_type_id=%s"
        return dbconn.execute(sql, self['hydra_type_id'])

    def set_status(self, status, dbconn=None):
        dbconn = dbconn if dbconn else db()
        sql = "UPDATE hydra_type SET status=%s WHERE hydra_type_id=%s"
        return dbconn.execute(sql, status, self['hydra_type_id'])

    @classmethod
    def get_runnable(cls, hydra_type_id, env, dbconn=None):
        sql = """SELECT hydra_type_id, hydra_type_name, next_run_sql
                   FROM hydra_type
                  WHERE next_run_dttm <= NOW()
                    AND status='live'
                    AND hydra_type_id=%s
                    AND run_env=%s
                    AND claimed_dttm IS NULL
                    AND next_run_sql IS NOT NULL"""
        dbconn = dbconn if dbconn else db()
        return dbconn.get(sql, hydra_type_id, env, cls=cls)

    def schedule_next(self, dbconn=None):
        dbconn = dbconn if dbconn else db()
        sql = """
            UPDATE hydra_type
               SET run_cnt=run_cnt+1,
                   last_run_dttm=next_run_dttm,
                   claimed_dttm=NULL,
                   next_run_dttm="""+self['next_run_sql']+"""
             WHERE hydra_type_id=%s"""
        return dbconn.execute(sql, self['hydra_type_id'])

    @staticmethod
    def clear_running(minutes=45, dbconn=None):
        dbconn = dbconn if dbconn else db()
        if type(dbconn) is aegis.database.PostgresConnection:
            sql = "UPDATE hydra_type SET status='live' WHERE status='running' and next_run_dttm < NOW() - INTERVAL '%s MINUTE'" % int(minutes)
        elif type(dbconn) is aegis.database.MysqlConnection:
            sql = "UPDATE hydra_type SET status='live' WHERE status='running' and next_run_dttm < NOW() - INTERVAL %s MINUTE" % int(minutes)
        return dbconn.execute(sql)

    def claim(self, dbconn=None):
        dbconn = dbconn if dbconn else db()
        sql = 'UPDATE hydra_type SET claimed_dttm=NOW() WHERE hydra_type_id=%s AND claimed_dttm IS NULL'
        return dbconn.execute(sql, self['hydra_type_id'])

    def unclaim(self, dbconn=None):
        dbconn = dbconn if dbconn else db()
        sql = 'UPDATE hydra_type SET claimed_dttm=NULL WHERE hydra_type_id=%s AND claimed_dttm IS NOT NULL'
        return dbconn.execute(sql, self['hydra_type_id'])

    @classmethod
    def past_items(cls, minutes=5, dbconn=None):
        dbconn = dbconn if dbconn else db()
        if type(dbconn) is aegis.database.PostgresConnection:
            sql = "SELECT * FROM hydra_type WHERE claimed_dttm < NOW() - INTERVAL '%s MINUTE' AND claimed_dttm > next_run_dttm" % int(minutes)
        elif type(dbconn) is aegis.database.MysqlConnection:
            sql = "SELECT * FROM hydra_type WHERE claimed_dttm < NOW() - INTERVAL %s MINUTE AND claimed_dttm > next_run_dttm" % int(minutes)
        return dbconn.query(sql, cls=cls)

    @staticmethod
    def clear_claims(minutes=5, dbconn=None):
        dbconn = dbconn if dbconn else db()
        if type(dbconn) is aegis.database.PostgresConnection:
            sql = "UPDATE hydra_type SET claimed_dttm=NULL WHERE claimed_dttm < NOW() - INTERVAL '%s MINUTE' AND status='live'" % int(minutes)
        elif type(dbconn) is aegis.database.MysqlConnection:
            sql = "UPDATE hydra_type SET claimed_dttm=NULL WHERE claimed_dttm < NOW() - INTERVAL %s MINUTE AND status='live'" % int(minutes)
        return dbconn.execute(sql)


class HydraQueue(aegis.database.Row):
    table_name = 'hydra_queue'
    id_column = 'hydra_queue_id'
    data_columns = ('hydra_type_id', 'priority_ndx', 'work_host', 'work_env', 'work_data', 'work_dttm', 'start_dttm', 'claimed_dttm', 'finish_dttm', 'try_cnt', 'error_cnt')

    @classmethod
    def scan_work_priority(cls, limit=10, hostname=None, env=None, dbconn=None):
        sql = """
        SELECT hydra_queue.*,
               hydra_type.hydra_type_name,
               hydra_type.hydra_type_desc
          FROM hydra_queue
          JOIN hydra_type USING (hydra_type_id)
         WHERE hydra_queue.work_dttm <= NOW()
           AND (hydra_queue.work_host=%s OR hydra_queue.work_host IS NULL)
           AND (hydra_queue.work_env=%s OR hydra_queue.work_env IS NULL)
           AND hydra_queue.claimed_dttm IS NULL
           AND hydra_queue.finish_dttm IS NULL
           AND hydra_queue.delete_dttm IS NULL
           AND hydra_type.status <> 'paused'
      ORDER BY hydra_queue.priority_ndx ASC
         LIMIT %s"""
        dbconn = dbconn if dbconn else db()
        return dbconn.query(sql, hostname, env, limit, cls=cls)

    @classmethod
    def scan_work(cls, limit=10, hostname=None, env=None, dbconn=None):
        sql = """
        SELECT hydra_queue.*,
               hydra_type.hydra_type_name,
               hydra_type.hydra_type_desc
          FROM hydra_queue
          JOIN hydra_type USING (hydra_type_id)
         WHERE hydra_queue.work_dttm <= NOW()
           AND (hydra_queue.work_host=%s OR hydra_queue.work_host IS NULL)
           AND (hydra_queue.work_env=%s OR hydra_queue.work_env IS NULL)
           AND hydra_queue.claimed_dttm IS NULL
           AND hydra_queue.finish_dttm IS NULL
           AND hydra_queue.delete_dttm IS NULL
           AND hydra_type.status <> 'paused'
      ORDER BY hydra_queue.work_dttm ASC
         LIMIT %s"""
        dbconn = dbconn if dbconn else db()
        return dbconn.query(sql, hostname, env, limit, cls=cls)

    @classmethod
    def scan(cls, limit=500, dbconn=None):
        dbconn = dbconn if dbconn else db()
        # XXX TODO using work_host, work_env
        if type(dbconn) is aegis.database.PostgresConnection:
            sql = "SELECT hydra_queue.*, hydra_type.hydra_type_name, hydra_type.next_run_sql, hydra_type.status FROM hydra_queue JOIN hydra_type USING (hydra_type_id) WHERE finish_dttm IS NULL AND hydra_queue.delete_dttm IS NULL ORDER BY priority_ndx, claimed_dttm DESC NULLS LAST, hydra_queue.work_dttm ASC LIMIT %s"
        elif type(dbconn) is aegis.database.MysqlConnection:
            sql = "SELECT hydra_queue.*, hydra_type.hydra_type_name, hydra_type.next_run_sql, hydra_type.status FROM hydra_queue JOIN hydra_type USING (hydra_type_id) WHERE finish_dttm IS NULL AND hydra_queue.delete_dttm IS NULL ORDER BY claimed_dttm DESC, hydra_queue.work_dttm ASC LIMIT %s"
        return dbconn.query(sql, limit, cls=cls)

    @classmethod
    def scan_work_type(cls, hydra_type_id):
        # XXX TODO using work_host, work_env
        sql = "SELECT * FROM hydra_queue WHERE work_dttm <= NOW() AND claimed_dttm IS NULL AND finish_dttm IS NULL AND delete_dttm IS NULL AND hydra_type_id=%s"
        return db().query(sql, hydra_type_id, cls=cls)

    @classmethod
    def scan_existing(cls, hydra_type_id, data):
        # XXX TODO using work_host, work_env
        sql = "SELECT * FROM hydra_queue WHERE finish_dttm IS NULL AND hydra_type_id=%s AND work_data=%s"
        return db().query(sql, hydra_type_id, data, cls=cls)

    @classmethod
    def count_live(cls, dbconn=None):
        dbconn = dbconn if dbconn else db()
        sql = "SELECT COUNT(*) AS queue_cnt FROM hydra_queue WHERE finish_dttm IS NULL AND delete_dttm IS NULL"
        return dbconn.get(sql, cls=cls)

    @classmethod
    def scan_type(cls, hydra_type_id, dbconn=None):
        dbconn = dbconn if dbconn else db()
        sql = "SELECT * FROM hydra_queue WHERE finish_dttm IS NULL AND delete_dttm IS NULL AND hydra_type_id=%s"
        return dbconn.query(sql, hydra_type_id, cls=cls)

    def claim(self, dbconn=None):
        dbconn = dbconn if dbconn else db()
        sql = 'UPDATE hydra_queue SET claimed_dttm=NOW() WHERE hydra_queue_id=%s AND claimed_dttm IS NULL'
        return dbconn.execute(sql, self['hydra_queue_id'])

    def unclaim(self, dbconn=None):
        dbconn = dbconn if dbconn else db()
        sql = 'UPDATE hydra_queue SET claimed_dttm=NULL WHERE hydra_queue_id=%s AND claimed_dttm IS NOT NULL'
        return dbconn.execute(sql, self['hydra_queue_id'])

    def incr_try_cnt(self, dbconn=None):
        dbconn = dbconn if dbconn else db()
        self['try_cnt'] += 1
        sql = 'UPDATE hydra_queue SET try_cnt=try_cnt+1 WHERE hydra_queue_id=%s'
        return dbconn.execute(sql, self['hydra_queue_id'])

    def incr_error_cnt(self, minutes=1, dbconn=None):
        dbconn = dbconn if dbconn else db()
        self['error_cnt'] += 1
        if type(dbconn) is aegis.database.PostgresConnection:
            sql = "UPDATE hydra_queue SET error_cnt=error_cnt+1, start_dttm=NULL, work_dttm=NOW() + INTERVAL '%s MINUTE' WHERE hydra_queue_id=%s"
        elif type(dbconn) is aegis.database.MysqlConnection:
            sql = "UPDATE hydra_queue SET error_cnt=error_cnt+1, start_dttm=NULL, work_dttm=NOW() + INTERVAL %s MINUTE WHERE hydra_queue_id=%s"
        return dbconn.execute(sql, minutes, self['hydra_queue_id'])

    def start(self, dbconn=None):
        dbconn = dbconn if dbconn else db()
        hydra_type = HydraType.get_id(self['hydra_type_id'], dbconn=dbconn)
        if hydra_type['next_run_sql']:
            hydra_type.set_status('running', dbconn=dbconn)
        sql = 'UPDATE hydra_queue SET start_dttm=NOW() WHERE hydra_queue_id=%s'
        return dbconn.execute(sql, self['hydra_queue_id'])

    def complete(self, dbconn=None):
        dbconn = dbconn if dbconn else db()
        hydra_type = HydraType.get_id(self['hydra_type_id'], dbconn=dbconn)
        if hydra_type['next_run_sql'] and hydra_type['status'] == 'running':
            hydra_type.set_status('live', dbconn=dbconn)
        sql = 'UPDATE hydra_queue SET finish_dttm=NOW() WHERE hydra_queue_id=%s'
        return dbconn.execute(sql, self['hydra_queue_id'])

    def finish(self, dbconn=None):
        dbconn = dbconn if dbconn else db()
        sql = 'UPDATE hydra_queue SET finish_dttm=NOW() WHERE hydra_queue_id=%s'
        return dbconn.execute(sql, self['hydra_queue_id'])

    @staticmethod
    def purge_completed(dbconn=None):
        dbconn = dbconn if dbconn else db()
        sql = "DELETE FROM hydra_queue WHERE finish_dttm IS NOT NULL AND finish_dttm < NOW()"
        return dbconn.execute(sql)

    @staticmethod
    def clear_claims(minutes=15, dbconn=None):
        dbconn = dbconn if dbconn else db()
        if type(dbconn) is aegis.database.PostgresConnection:
            sql = "UPDATE hydra_queue SET claimed_dttm=NULL, start_dttm=NULL WHERE claimed_dttm < NOW() - INTERVAL '%s MINUTE' AND finish_dttm IS NULL" % int(minutes)
        elif type(dbconn) is aegis.database.MysqlConnection:
            sql = "UPDATE hydra_queue SET claimed_dttm=NULL, start_dttm=NULL WHERE claimed_dttm < NOW() - INTERVAL %s MINUTE AND finish_dttm IS NULL" % int(minutes)
        return dbconn.execute(sql)

    @classmethod
    def past_items(cls, minutes=15, dbconn=None):
        dbconn = dbconn if dbconn else db()
        if type(dbconn) is aegis.database.PostgresConnection:
            sql = "SELECT * FROM hydra_queue WHERE work_dttm < NOW() - INTERVAL '%s MINUTE' AND claimed_dttm IS NOT NULL ORDER BY work_dttm ASC LIMIT 50" % int(minutes)
        elif type(dbconn) is aegis.database.MysqlConnection:
            sql = "SELECT * FROM hydra_queue WHERE work_dttm < NOW() - INTERVAL %s MINUTE AND claimed_dttm IS NOT NULL ORDER BY work_dttm ASC LIMIT 50" % int(minutes)
        return dbconn.query(sql, cls=cls)

    def run_now(self, dbconn=None):
        dbconn = dbconn if dbconn else db()
        sql = "UPDATE hydra_queue SET work_dttm=NOW(), claimed_dttm=NULL WHERE hydra_queue_id=%s"
        return dbconn.execute(sql, self['hydra_queue_id'])

    def singleton(self, dbconn=None):
        dbconn = dbconn if dbconn else db()
        sql = "SELECT * FROM hydra_queue WHERE hydra_type_id=%s AND hydra_queue_id <> %s AND claimed_dttm IS NOT NULL AND finish_dttm IS NULL AND delete_dttm IS NULL"
        return dbconn.query(sql, self['hydra_type_id'], self['hydra_queue_id'])


class ReportType(aegis.database.Row):
    table_name = 'report_type'
    id_column = 'report_type_id'

    @classmethod
    def insert(cls, report_type_name, report_sql, dbconn=None):
        dbconn = dbconn if dbconn else db()
        sql = "INSERT INTO report_type (report_type_name, report_sql) VALUES (%s, %s)"
        if type(db()) is aegis.database.PostgresConnection:
            sql += ' RETURNING report_type_id'
        return dbconn.execute(sql, report_type_name, report_sql)

    @classmethod
    def scan(cls, dbconn=None):
        dbconn = dbconn if dbconn else db()
        sql = "SELECT * FROM report_type"
        return dbconn.query(sql, cls=cls)

    @staticmethod
    def set_name(report_type_id, report_type_name, dbconn=None):
        dbconn = dbconn if dbconn else db()
        sql = 'UPDATE report_type SET report_type_name=%s WHERE report_type_id=%s'
        return dbconn.execute(sql, report_type_name, report_type_id)

    @staticmethod
    def set_sql(report_type_id, report_type_sql, dbconn=None):
        dbconn = dbconn if dbconn else db()
        sql = 'UPDATE report_type SET report_sql=%s WHERE report_type_id=%s'
        return dbconn.execute(sql, report_type_sql, report_type_id)


class Build(aegis.database.Row):
    table_name = 'build'
    id_column = 'build_id'

    @classmethod
    def scan(cls, dbconn=None):
        dbconn = dbconn if dbconn else db()
        sql = "SELECT * FROM build ORDER BY build_id DESC"
        return dbconn.query(sql, cls=cls)

    def set_output(self, build_step, output_tx, exit_status=None, dbconn=None):
        dbconn = dbconn if dbconn else db()
        # We have to be super explicit because MySQL CONCAT returns NULL if any param is NULL, even though Postgres ignores NULL and concatenates the other arguments
        if build_step == 'build':
            if self['build_output_tx'] is not None:
                sql = "UPDATE build SET build_output_tx=CONCAT(build_output_tx, %s), build_exit_status=%s WHERE build_id=%s AND build_output_tx IS NOT NULL"
            else:
                sql = "UPDATE build SET build_output_tx=%s, build_exit_status=%s WHERE build_id=%s AND build_output_tx IS NULL"
        elif build_step == 'deploy':
            if self['deploy_output_tx'] is not None:
                sql = "UPDATE build SET deploy_output_tx=CONCAT(deploy_output_tx, %s), deploy_exit_status=%s WHERE build_id=%s AND deploy_output_tx IS NOT NULL"
            else:
                sql = "UPDATE build SET deploy_output_tx=%s, deploy_exit_status=%s WHERE build_id=%s AND deploy_output_tx IS NULL"
        elif build_step == 'revert':
            if self['revert_output_tx'] is not None:
                sql = "UPDATE build SET revert_output_tx=CONCAT(revert_output_tx, %s), revert_exit_status=%s WHERE build_id=%s AND revert_output_tx IS NOT NULL"
            else:
                sql = "UPDATE build SET revert_output_tx=%s, revert_exit_status=%s WHERE build_id=%s AND revert_output_tx IS NULL"
        else:
            aegis.stdlib.logw(build_step, "BUILD_STEP NOT IN LIST")
            return
        return dbconn.execute(sql, output_tx, exit_status, self['build_id'])

    def set_version(self, version, dbconn=None):
        dbconn = dbconn if dbconn else db()
        sql = "UPDATE build SET version=%s WHERE build_id=%s AND version IS NULL"
        return dbconn.execute(sql, version, self['build_id'])

    def set_previous_version(self, previous_version, dbconn=None):
        dbconn = dbconn if dbconn else db()
        sql = "UPDATE build SET previous_version=%s WHERE build_id=%s AND previous_version IS NULL"
        return dbconn.execute(sql, previous_version, self['build_id'])

    def set_revision(self, revision, dbconn=None):
        dbconn = dbconn if dbconn else db()
        sql = "UPDATE build SET revision=%s WHERE build_id=%s AND revision IS NULL OR revision = 'HEAD'"
        return dbconn.execute(sql, revision, self['build_id'])

    def set_build_size(self, build_size, dbconn=None):
        dbconn = dbconn if dbconn else db()
        sql = "UPDATE build SET build_size=%s WHERE build_id=%s AND build_size IS NULL"
        return dbconn.execute(sql, build_size, self['build_id'])

    def set_message(self, message, build_step, dbconn=None):
        dbconn = dbconn if dbconn else db()
        sql = "UPDATE build SET " + build_step + "_message=%s WHERE build_id=%s AND " + build_step + "_message IS NULL"
        return dbconn.execute(sql, message, self['build_id'])

    def set_deployed(self, dbconn=None):
        dbconn = dbconn if dbconn else db()
        sql = "UPDATE build SET deploy_dttm=NOW() WHERE build_id=%s AND deploy_dttm IS NULL"
        return dbconn.execute(sql, self['build_id'])

    def set_reverted(self, dbconn=None):
        dbconn = dbconn if dbconn else db()
        sql = "UPDATE build SET revert_dttm=NOW() WHERE build_id=%s AND revert_dttm IS NULL"
        return dbconn.execute(sql, self['build_id'])

    def set_soft_deleted(self, dbconn=None):
        dbconn = dbconn if dbconn else db()
        sql = "UPDATE build SET delete_dttm=NOW() WHERE build_id=%s AND delete_dttm IS NULL"
        return dbconn.execute(sql, self['build_id'])

    def set_build_exec_sec(self, build_exec_sec, dbconn=None):
        dbconn = dbconn if dbconn else db()
        sql = "UPDATE build SET build_exec_sec=%s WHERE build_id=%s AND build_exec_sec IS NULL"
        return dbconn.execute(sql, build_exec_sec, self['build_id'])

    @classmethod
    def get_live_build(cls, env, dbconn=None):
        dbconn = dbconn if dbconn else db()
        sql = "SELECT * FROM build WHERE deploy_dttm IS NOT NULL AND deploy_exit_status=0 AND revert_dttm IS NULL AND env=%s AND build_target <> 'admin' ORDER BY deploy_dttm DESC LIMIT 1"
        return dbconn.get(sql, env, cls=cls)

    @classmethod
    def get_version(cls, version, dbconn=None):
        dbconn = dbconn if dbconn else db()
        sql = "SELECT * FROM build WHERE version=%s"
        return dbconn.get(sql, version, cls=cls)

    @classmethod
    def scan_dead_builds(cls, dbconn=None):
        dbconn = dbconn if dbconn else db()
        if type(dbconn) is aegis.database.PostgresConnection:
            sql = "SELECT * FROM build WHERE delete_dttm IS NOT NULL OR (deploy_dttm IS NULL AND create_dttm < NOW() - INTERVAL '1 WEEK')"
        elif type(dbconn) is aegis.database.MysqlConnection:
            sql = "SELECT * FROM build WHERE delete_dttm IS NOT NULL OR (deploy_dttm IS NULL AND create_dttm < NOW() - INTERVAL 1 WEEK)"
        return dbconn.query(sql, cls=cls)

    @classmethod
    def scan_stale_builds(cls, env, dbconn=None):
        dbconn = dbconn if dbconn else db()
        sql = "SELECT * FROM build WHERE env=%s AND deploy_dttm IS NOT NULL AND delete_dttm IS NULL ORDER BY deploy_dttm DESC"
        return dbconn.query(sql, env, cls=cls)

    @classmethod
    def deployed_envs(cls, dbconn=None):
        dbconn = dbconn if dbconn else db()
        sql = "SELECT DISTINCT env FROM build WHERE delete_dttm IS NULL"
        return dbconn.query(sql, cls=cls)


class Cache(aegis.database.Row):
    table_name = 'cache'
    id_column = 'cache_id'

    # External Interface for simplified usage
    @classmethod
    def get_cache(cls, cache_key):
        cls.purge_expired()
        cache_obj = cls.get_key(cache_key)
        if cache_obj:
            return json.loads(cache_obj['cache_json'])

    @classmethod
    def set_cache(cls, cache_key, cache_obj, duration_s):
        cache_json = json.dumps(cache_obj, cls=aegis.stdlib.DateTimeEncoder)
        cache_expiry = datetime.datetime.utcnow() + datetime.timedelta(seconds=duration_s) + datetime.timedelta(seconds=random.randint(0, duration_s))
        cache_id = cls.set_key(cache_key, cache_json, cache_expiry)
        return cls.get_cache(cache_key)

    @staticmethod
    def purge_all():
        sql = "DELETE FROM cache"
        return db().execute(sql)

    # Internal Interface
    @staticmethod
    def insert(cache_key, cache_json, cache_expiry):
        sql = "INSERT INTO cache (cache_key, cache_json, cache_expiry) VALUES (%s, %s, %s)"
        if type(db()) is aegis.database.PostgresConnection:
            sql += ' RETURNING cache_id'
        try:
            return db().execute(sql, cache_key, cache_json, cache_expiry)
        except aegis.database.PgsqlUniqueViolation as ex:
            logging.warning("Ignoring duplicate key in cache")
        except aegis.database.MysqlIntegrityError as ex:
            logging.warning("Ignoring duplicate key in cache")

    @classmethod
    def get_key(cls, cache_key):
        sql = "SELECT * FROM cache WHERE cache_key=%s"
        return db().get(sql, cache_key, cls=cls)

    @staticmethod
    def update_key(cache_key, cache_json, cache_expiry):
        sql = "UPDATE cache SET cache_json=%s, cache_expiry=%s WHERE cache_key=%s"
        return db().execute(sql, cache_json, cache_expiry, cache_key)

    @classmethod
    def set_key(cls, cache_key, cache_json, cache_expiry):
        cache_obj = cls.get_key(cache_key)
        if cache_obj:
            cls.update_key(cache_key, cache_json, cache_expiry)
            cache_obj = cls.get_key(cache_key)
        else:
            cls.insert(cache_key, cache_json, cache_expiry)
            cache_obj = cls.get_key(cache_key)
        return cache_obj

    @staticmethod
    def del_key(cache_key):
        sql = "DELETE FROM cache WHERE cache_key=%s"
        return db().execute(sql, cache_key)

    @staticmethod
    def purge_expired():
        sql = "DELETE FROM cache WHERE cache_expiry < NOW()"
        return db().execute(sql)


class AuditSession(aegis.database.Row):
    table_name = 'audit_session'
    id_column = 'audit_session_id'


class AuditRequest(aegis.database.Row):
    table_name = 'audit_request'
    id_column = 'audit_request_id'

class AuditRequestData(aegis.database.Row):
    table_name = 'audit_request_data'
    id_column = 'audit_request_data_id'

    @classmethod
    def get_audit_request_id(cls, audit_request_id, dbconn=None):
        dbconn = dbconn if dbconn else db()
        sql = "SELECT * FROM audit_request_data WHERE audit_request_id=%s"
        return dbconn.get(sql, audit_request_id, cls=cls)


class Monitor(aegis.database.Row):
    table_name = 'monitor'
    id_column = 'monitor_id'

    @classmethod
    def get_host_cmd(cls, host, cmd, dbconn=None):
        dbconn = dbconn if dbconn else db()
        sql = "SELECT * FROM monitor WHERE monitor_host=%s AND monitor_cmd=%s ORDER BY monitor_id DESC LIMIT 1"
        return dbconn.get(sql, host, cmd, cls=cls)


class Marketing(aegis.database.Row):
    table_name = 'marketing'
    id_column = 'marketing_id'

    @classmethod
    def get_name(cls, name, dbconn=None):
        dbconn = dbconn if dbconn else db()
        sql = 'SELECT * FROM marketing WHERE marketing_name=%s'
        return dbconn.get(sql, name, cls=cls)
