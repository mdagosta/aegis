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


class UserAgent(aegis.database.Row):
    table_name = 'user_agent'
    id_column = 'user_agent_id'

    @staticmethod
    def insert(user_agent_tx):
        user_agent_md5 = hashlib.md5(str(user_agent_tx).encode('utf-8')).hexdigest()
        sql = 'INSERT INTO user_agent (user_agent_tx, user_agent_md5) VALUES (%s, %s)'
        if type(db()) is aegis.database.PostgresConnection:
            sql += ' RETURNING user_agent_id'
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
            try:
                user_agent_id = cls.insert(user_agent_tx)
                user_agent_row = cls.get_id(user_agent_id)
            except (aegis.database.PgsqlIntegrityError, aegis.database.MysqlIntegrityError) as ex:
                user_agent_row = cls.get_agent(user_agent_tx)
                if not user_agent_row:
                    logging.exception(ex)
        return user_agent_row

    @staticmethod
    def set_robot_user_id(user_agent_id, robot_user_id):
        sql = 'UPDATE user_agent SET robot_user_id=%s WHERE user_agent_id=%s'
        return db().execute(sql, robot_user_id, user_agent_id)

    @staticmethod
    def set_robot_ind(user_agent_id, robot_ind):
        user_agent_id = int(user_agent_id)
        robot_ind = bool(robot_ind)
        if robot_ind not in [True, False]:
            return False
        sql = 'UPDATE user_agent SET robot_ind=%s WHERE user_agent_id=%s'
        return db().execute(sql, robot_ind, user_agent_id)

    def set_ua_json(self, ua_json):
        if self['user_agent_json'] or not ua_json:
            return
        sql = "UPDATE user_agent SET user_agent_json=%s WHERE user_agent_id=%s"
        return db().execute(sql, ua_json, self['user_agent_id'])


class User(aegis.database.Row):
    table_name = 'user_' if aegis.config.get('pg_database') else 'user'
    table_names = {'pgsql': 'user_', 'mysql': 'user'}
    id_column = 'user_id'

    @classmethod
    def insert(cls, user_agent_id):
        sql = 'INSERT INTO '+cls.table_name+' (user_agent_id) VALUES (%s)'
        if type(db()) is aegis.database.PostgresConnection:
            sql += ' RETURNING user_id'
        return db().execute(sql, user_agent_id)

    def set_member_id(self, member_id):
        sql = 'UPDATE '+self.table_name+' SET member_id=%s WHERE user_id=%s'
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
    def insert(email_id):
        sql = "INSERT INTO member (email_id) VALUES (%s) RETURNING member_id"
        return db().execute(sql, email_id)

    @classmethod
    def set_member(cls, email_id):
        member = cls.get_email_id(email_id)
        if not member:
            member_id = cls.insert(email_id)
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
        if member.get('email_id'):   # In case member table doesn't have email_id
            email = Email.get_id(member['email_id'])
            if email:
                member['email'] = email
        return member


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


class HydraType(aegis.database.Row):
    table_name = 'hydra_type'
    id_column = 'hydra_type_id'
    data_columns = ('hydra_type_name', 'hydra_type_desc', 'priority_ndx', 'next_run_sql', 'claimed_dttm')

    @classmethod
    def get_name(cls, hydra_type_name):
        sql = "SELECT * FROM hydra_type WHERE hydra_type_name=%s"
        return db().get(sql, hydra_type_name, cls=cls)

    @classmethod
    def scan(cls):
        sql = "SELECT * FROM hydra_type ORDER BY next_run_dttm ASC"
        return db().query(sql, cls=cls)

    def run_now(self):
        sql = "UPDATE hydra_type SET next_run_dttm=NOW(), status='live', claimed_dttm=NULL WHERE hydra_type_id=%s"
        return db().execute(sql, self['hydra_type_id'])

    def set_status(self, status):
        sql = "UPDATE hydra_type SET status=%s WHERE hydra_type_id=%s"
        return db().execute(sql, status, self['hydra_type_id'])

    @classmethod
    def get_runnable(cls, hydra_type_id):
        sql = """SELECT hydra_type_id, hydra_type_name, next_run_sql
                   FROM hydra_type
                  WHERE next_run_dttm <= NOW()
                    AND status='live'
                    AND hydra_type_id=%s
                    AND claimed_dttm IS NULL
                    AND next_run_sql IS NOT NULL"""
        return db().get(sql, hydra_type_id, cls=cls)

    def schedule_next(self):
        sql = """
            UPDATE hydra_type
               SET run_cnt=run_cnt+1,
                   last_run_dttm=next_run_dttm,
                   claimed_dttm=NULL,
                   next_run_dttm="""+self['next_run_sql']+"""
             WHERE hydra_type_id=%s
               AND status = 'live'"""
        return db().execute(sql, self['hydra_type_id'])

    @staticmethod
    def clear_running():
        if type(db()) is aegis.database.PostgresConnection:
            sql = "UPDATE hydra_type SET status='live' WHERE status='running' and next_run_dttm < NOW() - INTERVAL '45 MINUTE'"
        elif type(db()) is aegis.database.MysqlConnection:
            sql = "UPDATE hydra_type SET status='live' WHERE status='running' and next_run_dttm < NOW() - INTERVAL 45 MINUTE"
        return db().execute(sql)

    def claim(self):
        sql = 'UPDATE hydra_type SET claimed_dttm=NOW() WHERE hydra_type_id=%s AND claimed_dttm IS NULL'
        return db().execute(sql, self['hydra_type_id'])

    def unclaim(self):
        sql = 'UPDATE hydra_type SET claimed_dttm=NULL WHERE hydra_type_id=%s AND claimed_dttm IS NOT NULL'
        return db().execute(sql, self['hydra_type_id'])

    @staticmethod
    def clear_claims():
        if type(db()) is aegis.database.PostgresConnection:
            sql = "UPDATE hydra_type SET claimed_dttm=NULL WHERE claimed_dttm < NOW() - INTERVAL '5 MINUTE' AND status='live'"
        elif type(db()) is aegis.database.MysqlConnection:
            sql = "UPDATE hydra_type SET claimed_dttm=NULL WHERE claimed_dttm < NOW() - INTERVAL 5 MINUTE AND status='live'"
        return db().execute(sql)


class HydraQueue(aegis.database.Row):
    table_name = 'hydra_queue'
    id_column = 'hydra_queue_id'
    data_columns = ('hydra_type_id', 'priority_ndx', 'work_host', 'work_env', 'work_data', 'work_dttm', 'start_dttm', 'claimed_dttm', 'finish_dttm', 'try_cnt', 'error_cnt')

    @classmethod
    def scan_work_priority(cls, limit=10, hostname=None, env=None):
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
        return db().query(sql, hostname, env, limit, cls=cls)

    @classmethod
    def scan_work(cls, limit=10, hostname=None, env=None):
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
        return db().query(sql, hostname, env, limit, cls=cls)

    @classmethod
    def scan(cls, limit=100):
        # XXX TODO using work_host, work_env
        sql = "SELECT hydra_queue.*, hydra_type.hydra_type_name FROM hydra_queue JOIN hydra_type USING (hydra_type_id) WHERE finish_dttm IS NULL AND hydra_queue.delete_dttm IS NULL ORDER BY create_dttm ASC LIMIT %s"
        return db().query(sql, limit, cls=cls)

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

    def claim(self):
        sql = 'UPDATE hydra_queue SET claimed_dttm=NOW() WHERE hydra_queue_id=%s AND claimed_dttm IS NULL'
        return db().execute(sql, self['hydra_queue_id'])

    def unclaim(self):
        sql = 'UPDATE hydra_queue SET claimed_dttm=NULL WHERE hydra_queue_id=%s AND claimed_dttm IS NOT NULL'
        return db().execute(sql, self['hydra_queue_id'])

    def incr_try_cnt(self):
        self['try_cnt'] += 1
        sql = 'UPDATE hydra_queue SET try_cnt=try_cnt+1 WHERE hydra_queue_id=%s'
        return db().execute(sql, self['hydra_queue_id'])

    def incr_error_cnt(self, minutes=1):
        self['error_cnt'] += 1
        if type(db()) is aegis.database.PostgresConnection:
            sql = "UPDATE hydra_queue SET error_cnt=error_cnt+1, start_dttm=NULL, work_dttm=NOW() + INTERVAL '%s MINUTE' WHERE hydra_queue_id=%s"
        elif type(db()) is aegis.database.MysqlConnection:
            sql = "UPDATE hydra_queue SET error_cnt=error_cnt+1, start_dttm=NULL, work_dttm=NOW() + INTERVAL %s MINUTE WHERE hydra_queue_id=%s"
        return db().execute(sql, minutes, self['hydra_queue_id'])

    def start(self):
        hydra_type = HydraType.get_id(self['hydra_type_id'])
        if hydra_type['next_run_sql']:
            hydra_type.set_status('running')
        sql = 'UPDATE hydra_queue SET start_dttm=NOW() WHERE hydra_queue_id=%s'
        return db().execute(sql, self['hydra_queue_id'])

    def complete(self):
        hydra_type = HydraType.get_id(self['hydra_type_id'])
        if hydra_type['next_run_sql'] and hydra_type['status'] == 'running':
            hydra_type.set_status('live')
        sql = 'UPDATE hydra_queue SET finish_dttm=NOW() WHERE hydra_queue_id=%s'
        return db().execute(sql, self['hydra_queue_id'])

    @staticmethod
    def purge_completed():
        sql = "DELETE FROM hydra_queue WHERE finish_dttm IS NOT NULL AND finish_dttm < NOW()"
        return db().execute(sql)

    @staticmethod
    def clear_claims():
        if type(db()) is aegis.database.PostgresConnection:
            sql = "UPDATE hydra_queue SET claimed_dttm=NULL, start_dttm=NULL WHERE claimed_dttm < NOW() - INTERVAL '15 MINUTE' AND finish_dttm IS NULL"
        elif type(db()) is aegis.database.MysqlConnection:
            sql = "UPDATE hydra_queue SET claimed_dttm=NULL, start_dttm=NULL WHERE claimed_dttm < NOW() - INTERVAL 15 MINUTE AND finish_dttm IS NULL"
        return db().execute(sql)

    @classmethod
    def past_items(cls):
        if type(db()) is aegis.database.PostgresConnection:
            sql = "SELECT * FROM hydra_queue WHERE work_dttm < NOW() - INTERVAL '5 MINUTE'"
        elif type(db()) is aegis.database.MysqlConnection:
            sql = "SELECT * FROM hydra_queue WHERE work_dttm < NOW() - INTERVAL 5 MINUTE"
        return db().query(sql, cls=cls)

    def run_now(self):
        sql = "UPDATE hydra_queue SET work_dttm=NOW(), claimed_dttm=NULL WHERE hydra_queue_id=%s"
        return db().execute(sql, self['hydra_queue_id'])

    def singleton(self):
        sql = "SELECT * FROM hydra_queue WHERE hydra_type_id=%s AND hydra_queue_id <> %s AND claimed_dttm IS NOT NULL AND finish_dttm IS NULL AND delete_dttm IS NULL"
        return db().query(sql, self['hydra_type_id'], self['hydra_queue_id'])


class ReportType(aegis.database.Row):
    table_name = 'report_type'
    id_column = 'report_type_id'

    @classmethod
    def insert(cls, report_type_name, report_sql):
        sql = "INSERT INTO report_type (report_type_name, report_sql) VALUES (%s, %s) RETURNING report_type_id"
        return db().execute(sql, report_type_name, report_sql)

    @classmethod
    def scan(cls):
        sql = "SELECT * FROM report_type"
        return db().query(sql, cls=cls)

    @staticmethod
    def set_name(report_type_id, report_type_name):
        sql = 'UPDATE report_type SET report_type_name=%s WHERE report_type_id=%s'
        return db().execute(sql, report_type_name, report_type_id)

    @staticmethod
    def set_sql(report_type_id, report_type_sql):
        sql = 'UPDATE report_type SET report_sql=%s WHERE report_type_id=%s'
        return db().execute(sql, report_type_sql, report_type_id)


class Build(aegis.database.Row):
    table_name = 'build'
    id_column = 'build_id'

    @classmethod
    def scan(cls):
        sql = "SELECT * FROM build ORDER BY build_id DESC"
        return db().query(sql, cls=cls)

    def set_output(self, build_step, output_tx, exit_status=None):
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
        return db().execute(sql, output_tx, exit_status, self['build_id'])

    def set_version(self, version):
        sql = "UPDATE build SET version=%s WHERE build_id=%s AND version IS NULL"
        return db().execute(sql, version, self['build_id'])

    def set_previous_version(self, previous_version):
        sql = "UPDATE build SET previous_version=%s WHERE build_id=%s AND previous_version IS NULL"
        return db().execute(sql, previous_version, self['build_id'])

    def set_revision(self, revision):
        sql = "UPDATE build SET revision=%s WHERE build_id=%s AND revision IS NULL OR revision = 'HEAD'"
        return db().execute(sql, revision, self['build_id'])

    def set_build_size(self, build_size):
        sql = "UPDATE build SET build_size=%s WHERE build_id=%s AND build_size IS NULL"
        return db().execute(sql, build_size, self['build_id'])

    def set_message(self, message, build_step):
        sql = "UPDATE build SET " + build_step + "_message=%s WHERE build_id=%s AND " + build_step + "_message IS NULL"
        return db().execute(sql, message, self['build_id'])

    def set_deployed(self):
        sql = "UPDATE build SET deploy_dttm=NOW() WHERE build_id=%s AND deploy_dttm IS NULL"
        return db().execute(sql, self['build_id'])

    def set_reverted(self):
        sql = "UPDATE build SET revert_dttm=NOW() WHERE build_id=%s AND revert_dttm IS NULL"
        return db().execute(sql, self['build_id'])

    def set_soft_deleted(self):
        sql = "UPDATE build SET delete_dttm=NOW() WHERE build_id=%s AND delete_dttm IS NULL"
        return db().execute(sql, self['build_id'])

    def set_build_exec_sec(self, build_exec_sec):
        sql = "UPDATE build SET build_exec_sec=%s WHERE build_id=%s AND build_exec_sec IS NULL"
        return db().execute(sql, build_exec_sec, self['build_id'])

    @classmethod
    def get_live_build(cls, env):
        sql = "SELECT * FROM build WHERE deploy_dttm IS NOT NULL AND deploy_exit_status=0 AND revert_dttm IS NULL AND env=%s ORDER BY deploy_dttm DESC LIMIT 1"
        return db().get(sql, env, cls=cls)

    @classmethod
    def get_version(cls, version):
        sql = "SELECT * FROM build WHERE version=%s"
        return db().get(sql, version, cls=cls)

    @classmethod
    def scan_dead_builds(cls):
        sql = "SELECT * FROM build WHERE delete_dttm IS NOT NULL OR (deploy_dttm IS NULL AND create_dttm < NOW() - INTERVAL 1 WEEK)"
        return db().query(sql, cls=cls)

    @classmethod
    def scan_stale_builds(cls, env):
        sql = "SELECT * FROM build WHERE env=%s AND deploy_dttm IS NOT NULL ORDER BY deploy_dttm DESC"
        return db().query(sql, env, cls=cls)

    @classmethod
    def deployed_envs(cls):
        sql = "SELECT DISTINCT env FROM build WHERE delete_dttm IS NULL"
        return db().query(sql, cls=cls)


class Cache(aegis.database.Row):
    table_name = 'cache'
    id_column = 'cache_id'

    @staticmethod
    def insert(cache_key, cache_json, cache_expiry):
        sql = "INSERT INTO cache (cache_key, cache_json, cache_expiry) VALUES (%s, %s, %s) RETURNING cache_id"
        return db().execute(sql, cache_key, cache_json, cache_expiry)

    @classmethod
    def get_key(cls, cache_key):
        sql = "SELECT * FROM cache WHERE cache_key=%s"
        return db().get(sql, cache_key, cls=cls)

    @staticmethod
    def update_key(cache_key, cache_json, cache_expiry):
        sql = "UPDATE cache SET cache_json=%s, cache_expiry=%s WHERE cache_key=%s"
        return db().execute(sql, cache_json, cache_expiry, cache_key)

    @staticmethod
    def del_key(cache_key):
        sql = "DELETE FROM cache WHERE cache_key=%s"
        return db().execute(sql, cache_key)

    @staticmethod
    def purge_expired():
        sql = "DELETE FROM cache WHERE cache_expiry < NOW()"
        return db().execute(sql)
