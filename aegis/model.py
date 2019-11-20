#-*- coding: utf-8 -*-
#
# Core common Data Model that will applies to a lot of applications


# Python Imports
import hashlib
import logging
import uuid

# Project Imports
import aegis.stdlib
import aegis.database

db = aegis.database.db


class UserAgent(aegis.database.Row):
    table_name = 'user_agent'
    id_column = 'user_agent_id'

    @staticmethod
    def insert(user_agent_tx):
        user_agent_md5 = hashlib.md5(str(user_agent_tx).encode('utf-8')).hexdigest()
        sql = 'INSERT INTO user_agent (user_agent_tx, user_agent_md5) VALUES (%s, %s) RETURNING user_agent_id'
        return db().execute(sql, user_agent_tx, user_agent_md5)

    @classmethod
    def get_agent(cls, user_agent_tx):
        user_agent_md5 = hashlib.md5(str(user_agent_tx).encode('utf-8')).hexdigest()
        sql = 'SELECT * FROM user_agent WHERE user_agent_md5=%s'
        return db().get(sql, user_agent_md5, cls=cls)

    @classmethod
    def set_user_agent(cls, user_agent_tx):
        user_agent_row = cls.get_agent(user_agent_tx)
        if not user_agent_row:
            user_agent_id = cls.insert(user_agent_tx)
            user_agent_row = cls.get_id(user_agent_id)
        return user_agent_row

    @staticmethod
    def set_robot_user_id(user_agent_id, robot_user_id):
        sql = 'UPDATE user_agent SET robot_user_id=%s WHERE user_agent_id=%s'
        return db().execute(sql, robot_user_id, user_agent_id)

    @staticmethod
    def set_robot_ind(user_agent_id, robot_ind):
        user_agent_id = long(user_agent_id)
        robot_ind = long(robot_ind)
        if robot_ind not in [-1, 0, 1]:
            return False
        sql = 'UPDATE user_agent SET robot_ind=%s WHERE user_agent_id=%s'
        return db().execute(sql, robot_ind, user_agent_id)


class User(aegis.database.Row):
    table_name = 'user_'
    id_column = 'user_id'

    @staticmethod
    def insert(user_agent_id):
        sql = 'INSERT INTO user_ (user_agent_id) VALUES (%s) RETURNING user_id'
        return db().execute(sql, user_agent_id)

    def set_member_id(self, member_id):
        sql = 'UPDATE user_ SET member_id=%s WHERE user_id=%s'
        return db().execute(sql, member_id, self['user_id'])


class Email(aegis.database.Row):
    table_name = 'email'
    id_column = 'email_id'

    @staticmethod
    def insert(email):
        sql = "INSERT INTO email (email) VALUES (%s) RETURNING email_id"
        return db().execute(sql, email)

    @classmethod
    def set_email(cls, email):
        email_row = cls.get_email(email)
        if not email_row:
            email_id = cls.insert(email)
            email_row = cls.get_id(email_id)
        return email_row

    @classmethod
    def get_email(cls, email):
        sql = "SELECT * FROM email WHERE email=%s"
        return db().get(sql, email, cls=cls)

    @classmethod
    def get_member_id(cls, member_id):
        sql = "SELECT * FROM email WHERE member_id=%s"
        return db().get(sql, member_id, cls=cls)

    def set_member_id(self, member_id):
        sql = "UPDATE email SET member_id=%s WHERE email_id=%s"
        return db().execute(sql, member_id, self['email_id'])


class Member(aegis.database.Row):
    table_name = 'member'
    id_column = 'member_id'

    @staticmethod
    def insert(email_id, full_name, country_cd, pricing_strategy):
        sql = "INSERT INTO member (email_id, full_name, country_cd, pricing_strategy) VALUES (%s, %s, %s, %s) RETURNING member_id"
        return db().execute(sql, email_id, full_name, country_cd, pricing_strategy)

    @classmethod
    def set_member(cls, email_id, full_name, country_cd, pricing_strategy):
        member = cls.get_email_id(email_id)
        if not member:
            member_id = cls.insert(email_id, full_name, country_cd, pricing_strategy)
            member = cls.get_id(member_id)
        return member

    @classmethod
    def get_email_id(cls, email_id):
        sql = "SELECT * FROM member WHERE email_id = %s"
        return db().get(sql, email_id, cls=cls)

    @classmethod
    def get_auth(cls, member_id):
        if not member_id:
            return None
        member = cls.get_id(member_id)
        if not member:
            return None
        # If member has email then return the email info
        return member

    def set_vat(self, vat):
        sql = "UPDATE member SET vat=%s WHERE member_id=%s"
        return db().execute(sql, vat, self['member_id'])

    
class EmailType(aegis.database.Row):
    table_name = 'email_type'
    id_column = 'email_type_id'

    @classmethod
    def scan(cls):
        sql = "SELECT * FROM email_type"
        return db().query(sql, cls=cls)

    @classmethod
    def get_name(cls, email_type_name):
        sql = "SELECT * FROM email_type WHERE email_type_name=%s"
        return db().get(sql, email_type_name, cls=cls)


class EmailTracking(aegis.database.Row):
    table_name = 'email_tracking'
    id_column = 'email_tracking_id'

    @staticmethod
    def insert(email_type_id, from_email_id, to_email_id, email_data):
        sql = "INSERT INTO email_tracking (email_type_id, from_email_id, to_email_id, email_uuid, email_data, send_dttm) VALUES (%s, %s, %s, %s, %s, NOW()) RETURNING email_tracking_id"
        return db().execute(sql, email_type_id, from_email_id, to_email_id, uuid.uuid4().hex, email_data)

    def mark_sent(self):
        sql = "UPDATE email_tracking SET sent_dttm=NOW() WHERE email_tracking_id=%s AND sent_dttm IS NULL"
        return db().execute(sql, self['email_tracking_id'])


class EmailLink(aegis.database.Row):
    table_name = 'email_link'
    id_column = 'email_link_id'

    @staticmethod
    def insert(email_id):
        sql = "INSERT INTO email_link (email_id, magic_token) VALUES (%s, %s) RETURNING email_link_id"
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
      sql = "INSERT INTO pageview (user_id, member_id, url_path, url_query, url_tx, request_name) VALUES (%s, %s, %s, %s, %s, %s) RETURNING pageview_id"
      return db().execute(sql, user_id, member_id, url_path, url_query, url_tx, request_name)
    
