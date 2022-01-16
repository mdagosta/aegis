#!/usr/bin/env python3
#-*- coding: utf-8 -*-
#
# Aegis is your shield to protect you on the Brave New Web

# Python Imports
import asyncio
import base64
import copy
import datetime
import functools
import json
import logging
import os
import signal
import sys
import time
import traceback

# Extern Imports
import requests
from tornado.options import options
import tornado.web
import tornado.platform.asyncio
import user_agents
import zlib

# Project Imports
import aegis.stdlib
import aegis.model
import aegis.config
import aegis.database
import aegis.build
import config


class AegisHandler(tornado.web.RequestHandler):

    def __init__(self, *args, **kwargs):
        # Initialize timer_obj on self, since this could be called before a subclass calls on self.timer_obj
        self._parent_timer = not hasattr(self, 'timer_obj')
        if not hasattr(self, 'timer_obj'):
            self.timer_obj = aegis.stdlib.TimerObj()
        if self._parent_timer:
            aegis.stdlib.timer_start(self.timer_obj, 'init')
        super(AegisHandler, self).__init__(*args, **kwargs)
        self.tmpl = {}
        self.tmpl['logw'] = self.logw = aegis.stdlib.logw
        hostname = self.request.host.split(':')[0]
        self.tmpl['host'] = hostname
        if not aegis.config.get('skip_hostname_check'):
            # Don't allow direct IP address in the Host header
            if aegis.stdlib.validate_ip_address(self.tmpl['host']):
                logging.warning("Disallow IP Address in Host Header: %s", self.tmpl['host'])
                raise tornado.web.HTTPError(400)
            # Implement *.domain.com to still work on domain.com
            host_split = hostname.split('.')
            valid_subdomains = aegis.config.get('valid_subdomains')
            if len(host_split) > 2 and valid_subdomains and host_split[0] not in valid_subdomains:
                self.tmpl['host'] = '.'.join(host_split[1:])
            # Ignore hostnames not in config.py. Only use the ones we have specified.
            if self.tmpl['host'] not in config.hostnames.keys():
                logging.warning("Ignore hostname not specified in config.py: %s", self.tmpl['host'])
                raise tornado.web.HTTPError(404)
        config.apply_hostname(self.tmpl['host'])
        if not aegis.config.get('skip_hostname_check'):
            self.tmpl['domain'] = options.domain
        self.tmpl['options'] = options
        self.tmpl['program_name'] = options.program_name
        self.tmpl['app_name'] = options.app_name
        self.tmpl['env'] = config.get_env()
        self.tmpl['referer'] = self.request.headers.get('Referer')
        self.tmpl['user_agent'] = self.request.headers.get('User-Agent')
        self.tmpl['scheme'] = 'https://'
        self.tmpl['get_current_user'] = self.get_current_user
        self.tmpl['xsrf_token'] = self.xsrf_token
        self.tmpl['nl2br'] = aegis.stdlib.nl2br
        self.tmpl['format_integer'] = aegis.stdlib.format_integer
        self.tmpl['get_user_id'] = self.get_user_id
        self.tmpl['get_member_id'] = self.get_member_id
        self.tmpl['get_member_email'] = self.get_member_email
        self.tmpl['utcnow'] = datetime.datetime.utcnow()
        self.models = {}
        self.models['UserAgent'] = aegis.model.UserAgent
        self.models['User'] = aegis.model.User
        if self._parent_timer:
            aegis.stdlib.timer_stop(self.timer_obj, 'init')

    def prepare(self):
        if self._parent_timer:
            aegis.stdlib.timer_start(self.timer_obj, 'prepare')
        self.set_header('Cache-Control', 'no-cache, no-store')
        self.set_header('Pragma', 'no-cache')
        self.set_header('Expires', 'Fri, 21 Dec 2012 03:08:13 GMT')
        self.tmpl['request_name'] = self.page_name = '%s.%s' % (self.__class__.__name__, self.request.method)
        self.tmpl['next_url'] = self.get_next_url()
        self.request.args = dict([(key, self.get_argument(key, strip=False)) for key, val in self.request.arguments.items()])
        self.setup_user()
        super(AegisHandler, self).prepare()
        if self._parent_timer:
            aegis.stdlib.timer_stop(self.timer_obj, 'prepare')

    def finish(self, chunk=None):
        # Fail fast for maintenance errors
        if self.get_status() in (503,):
            super(AegisHandler, self).finish(chunk)
            return
        if self._parent_timer:
            aegis.stdlib.timer_start(self.timer_obj, 'finish')
        auth_ck = self.cookie_get('auth')
        logged_out = (self.tmpl.get('logged_out') == True)
        if auth_ck and not logged_out:
            # If there's a member_auth, refresh the expiration in the backend along with the cookie
            if hasattr(self, '_member_auth'):
                self._member_auth.refresh(options.cookie_durations['auth'] * 86400)
            # Update auth cookie as long as it isn't being overwritten
            new_cookie_value = self._new_cookie.get(self.cookie_name('auth'))
            if not new_cookie_value:
                self.cookie_set('auth', auth_ck)
            else:
                new_cookie_value = new_cookie_value.value.split(':')[-1].split('|')[0]
                decoded = self.cookie_decode(base64.b64decode(new_cookie_value))
                if decoded == auth_ck:
                    self.cookie_set('auth', auth_ck)
        if 'session_ck' in self.tmpl:
            if self.tmpl.get('session_ck'):
                self.cookie_set('session', self.tmpl['session_ck'])
            else:
                self.cookie_clear('session')
        # Cookie Debug
        if aegis.config.get('cookie_debug'):
            cookies = []
            if hasattr(self, "_new_cookie"):
                for cookie in self._new_cookie.values():
                    cookies.append("Set-Cookie: %s" % cookie.OutputString(None))
            self.logw(cookies, "HTTP Reponse Set-Cookie Header")
        if self._parent_timer:
            aegis.stdlib.timer_stop(self.timer_obj, 'finish')
        super(AegisHandler, self).finish(chunk)

    def on_finish(self):
        # This runs after the response has been sent to the client, intended for cleanup.
        #logging.warning("ON FINISH")
        pass

    def debug_request(self):
        req_str = str(self.request).rstrip(')') + ', headers={'
        for header in sorted(self.request.headers.items()):
            req_str += "'%s': '%s', " % header
        req_str = "%s})" % req_str.rstrip(', ')
        logging.warning(req_str)

    def setup_user(self):
        # Set up user-cookie tracking system, based on user-agent. This function takes ~2-5ms depending on cpu and database speed and latency.
        if not self.tmpl['user_agent']:
            self.tmpl['user_agent'] = 'NULL USER AGENT'
        self.tmpl['user_agent_obj'] = ua = user_agents.parse(self.tmpl['user_agent'])
        ua_json = {'is_mobile': ua.is_mobile, 'is_tablet': ua.is_tablet, 'is_pc': ua.is_pc, 'is_touch': ua.is_touch_capable,
                   'is_email': ua.is_email_client, 'is_robot': ua.is_bot,
                   'os_name': ua.get_os(), 'os_family': ua.os.family, 'os_version': ua.os.version_string,
                   'browser_name': ua.get_browser(), 'browser_family': ua.browser.family, 'browser_version': ua.browser.version_string}
        if not (aegis.config.get('pg_database') or aegis.config.get('mysql_database')):
            return
        self.tmpl['user'] = {}
        user_agent = self.models['UserAgent'].set_user_agent(self.tmpl['user_agent'])
        # if ua_json not set, set it
        if not user_agent['user_agent_json'] and ua_json:
            ua_json = json.dumps(ua_json, cls=aegis.stdlib.DateTimeEncoder)
            user_agent.set_ua_json(ua_json)
        if self.user_is_robot():
            self.models['UserAgent'].set_robot_ind(user_agent['user_agent_id'], True)
            user_agent = self.models['UserAgent'].get_id(user_agent['user_agent_id'])
        # Set up all robots to use the same user_id, based on the user-agent string, and don't bother with cookies.
        # Regular users just get tagged with a user cookie matching a row.
        user = None
        if user_agent['robot_ind']:
            if not user_agent['robot_user_id']:
                user_id = self.models['User'].insert(user_agent['user_agent_id'])
                self.models['UserAgent'].set_robot_user_id(user_agent['user_agent_id'], user_id)
                user_agent = self.models['UserAgent'].get_id(user_agent['user_agent_id'])
            user = self.models['User'].get_id(user_agent['robot_user_id'])
            user_ck = {}
        else:
            # Check if the cookie exists, and if the record exists. If either doesn't exist, start a new user record.
            user_ck = self.cookie_get('user')
            if user_ck and user_ck.get('user_id'):
                user = self.models['User'].get_id(user_ck['user_id'])
                if user:
                    self.cookie_set('user', user_ck)
            if not user:
                user_id = self.models['User'].insert(user_agent['user_agent_id'])
                user = self.models['User'].get_id(user_id)
                if user_ck:
                    user_ck['user_id'] = user_id
                else:
                    user_ck = {'user_id': user_id}
                self.cookie_set('user', user_ck)
        if user:
            self.tmpl['user']['user_id'] = user['user_id']
        # At the end leave the row behind for later user in the request
        self.tmpl['user_agent_row'] = user_agent


    def enforce_admin(self):
        if not self.is_super_admin():
            raise tornado.web.HTTPError(403)

    def user_is_robot(self):
        # If this fails so early that setup_user() doesn't run, just parse the user_agent here
        if not self.tmpl.get('user_agent_obj'):
            self.tmpl['user_agent_obj'] = user_agents.parse(self.tmpl['user_agent'])
        return bool(self.tmpl['user_agent_obj'].is_bot or aegis.stdlib.is_robot(self.tmpl['user_agent']))

    def get_template_path(self):
        return options.template_path

    def render(self, template_name, **kwargs):
        aegis.stdlib.timer_start(self.timer_obj, 'render')
        template_path = os.path.join(options.template_path, template_name)
        # Override parent class render to remove the embeds and instrument a timer here. Copied in from tornado/web.py render()
        if self._finished:
            raise RuntimeError("Cannot render() after finish()")
        html = self.render_string(template_name, **kwargs)
        aegis.stdlib.timer_stop(self.timer_obj, 'render')
        self.finish(html)

    def render_path(self, template_name, **kwargs):
        template_path = os.path.join(self.get_template_path(), template_name)
        self.render(template_path, **kwargs)

    def _handle_request_exception(self, ex):
        if type(ex) in (aegis.database.PgsqlAdminShutdown, aegis.database.PgsqlOperationalError, aegis.database.MysqlOperationalError, aegis.database.MysqlInterfaceError):
            logging.error("Database is down. Send HTTP 503.")
            self.send_error(503)
            return
        aegis.model.db().close()  # Closing database effectively does a transaction ROLLBACK
        #self.logw(ex, "EX")
        #logging.exception(ex)
        # Remove cookie info to anonymize and make message shorter and more useful. Almost never used in debug.
        if self.request.headers.get('Cookie'):
            del self.request.headers['Cookie']
        # Don't post boring pseudo-errors to channels
        if isinstance(ex, tornado.web.HTTPError) and ex.status_code in [401, 403, 404, 405]:
            logging.warning("Prevent too-annoying errors from POSTing to Chat")
            super(AegisHandler, self)._handle_request_exception(ex)
            return
        # Send errors to chat hooks, based on them being configured for the environment
        header = "`[%s ENV   %s   %s   uid: %s   mid: %s]`" % (config.get_env().upper(), self.request.uri, self.tmpl['request_name'], self.get_user_id() or '-', self.get_member_id() or '-')
        template_opts = {'handler': self, 'traceback': traceback.format_exc(), 'kwargs': {}, 'header': header}
        error_message = self.render_string("error_message.txt", **template_opts).decode('utf-8')
        if config.get_env() == 'prod':
            hooks = ['alerts_chat_hook']
        else:
            hooks = ['debug_chat_hook']
        for hook in hooks:
            hook_url = aegis.config.get(hook)
            # Call own function? So the client can write custom error messages.
            if hook_url:
                requests.post(hook_url, json={"text": error_message})
        super(AegisHandler, self)._handle_request_exception(ex)

    def get_next_url(self, default_url='/'):
        next_url = self.get_argument('next', None)
        if next_url:
            return tornado.escape.url_unescape(next_url)
        if self.tmpl['referer']:
            return tornado.escape.url_unescape(self.tmpl['referer'])
        return default_url


    # Cookie Handling
    def cookie_encode(self, val):
        return tornado.escape.url_escape(tornado.escape.json_encode(val))

    def cookie_decode(self, val):
        if val is None:
            return None
        ck = tornado.escape.json_decode(tornado.escape.url_unescape(val))
        if type(ck) is dict:
            ck = dict([(str(key), ck[key]) for key in ck])
        return ck

    def cookie_name(self, name):
        if self.tmpl['env'] in ('prod', 'prod-admin'):
            return name
        # Authentication for special -admin environment to use cookies from the main env
        if self.tmpl['env'].endswith('-admin'):
            name = "%s_%s" % (self.tmpl['env'].rsplit('-', maxsplit=1)[0], name)
        else:
            name = "%s_%s" % (self.tmpl['env'], name)
        return name

    def cookie_set(self, name, value, cookie_duration=None):
        # Session cookie is set to None duration to implement a browser session cookie
        if not cookie_duration:
            cookie_durations = aegis.config.get('cookie_durations')
            if not cookie_durations:
                cookie_durations = {'user': 3650, 'session': None, 'auth': 90}
            cookie_duration = cookie_durations[name]
        cookie_flags = {'httponly': True, 'secure': True}
        if options.hostname == 'localhost':
            cookie_flags['secure'] = False
        cookie_val = self.cookie_encode(value)
        self.set_secure_cookie(self.cookie_name(name), cookie_val, expires_days=cookie_duration, domain=options.hostname, **cookie_flags)

    def cookie_get(self, name, cookie_duration=None):
        # Session cookie is set to 30 since browser should expire session cookie not time-limit
        if not cookie_duration:
            cookie_durations = aegis.config.get('cookie_durations')
            if not cookie_durations:
                cookie_durations = {'user': 3650, 'session': 30, 'auth': 90}
            cookie_duration = cookie_durations[name]
        cookie_val = self.get_secure_cookie(self.cookie_name(name), max_age_days=cookie_duration)
        cookie_val = tornado.escape.to_basestring(cookie_val)
        cookie_val = self.cookie_decode(cookie_val)
        return cookie_val

    def cookie_clear(self, name):
        self.clear_cookie(self.cookie_name(name), domain=options.hostname)


    # Authentication
    def get_user_id(self):
        return self.tmpl.get('user', {}).get('user_id')

    def member_auth(self, member_auth_type_id, member_id, email_id, register_flag=False, login_flag=False):
        auth_duration_sec = options.cookie_durations['auth'] * 86400
        member_auth = {'member_auth_type_id': member_auth_type_id, 'email_id': email_id, 'register_flag': bool(register_flag), 'login_flag': bool(login_flag),
                       'member_id': member_id, 'user_id': self.get_user_id(), 'ip_address': self.request.remote_ip,
                       'expire_dttm': datetime.datetime.utcnow() + datetime.timedelta(seconds=auth_duration_sec)}
        return aegis.model.MemberAuth.insert(**member_auth)

    def validate_member_auth_ck(self):
        # Cookie can't change mid-request so we can just cache the value on the handler
        if hasattr(self, '_member_id') and hasattr(self, '_member_auth_id') and hasattr(self, '_member_auth'):
            return (self._member_id, self._member_auth_id, self._member_auth)
        # No cookie, no authie
        if not self.cookie_get("auth"):
            return None
        # Default is to only have a member_id. Alternately member_id|member_auth_id|magic_token
        self._member_id = aegis.stdlib.validate_int(self.cookie_get("auth"))
        if self._member_id:
            return self._member_id
        # Unpack and check the auth and token
        member_id, member_auth_id, magic_token = self.cookie_get("auth").split('|')
        member_id = aegis.stdlib.validate_int(member_id)
        member_auth_id = aegis.stdlib.validate_int(member_auth_id)
        member_auth = None
        if member_id and member_auth_id:
            member_auth = aegis.model.MemberAuth.get_auth(member_id, member_auth_id, magic_token)
        if not member_auth:
            raise Exception("MemberAuth doesn't match, is expired, or is deleted: %s|%s|%s" % (member_id, member_auth_id, magic_token))
        self._member_id = member_id
        self._member_auth_id = member_auth_id
        self._member_auth = member_auth
        return (self._member_id, self._member_auth_id, self._member_auth)

    def get_member_id(self):
        # Cookie can't change mid-request so we can just cache the value on the handler
        if hasattr(self, '_member_id'):
            return self._member_id
        # When not on production, if test token and test member_id are present, use that for the request.
        test_token = self.request.headers.get('Test-Token')
        test_member_id = aegis.stdlib.validate_int(self.request.headers.get('Test-Member-Id'))
        if self.tmpl['env'] != 'prod' and test_token and test_token == options.test_token and test_member_id:
            # Check member exists so we don't just explode from exuberant testing!
            if aegis.model.Member.get_id(test_member_id):
                logging.warning("Test Mode | MemberId Override: %s", test_member_id)
                self._member_id = test_member_id
                return self._member_id
        ck = self.cookie_get("auth")
        #self.logw(ck, "Auth Cookie")
        if ck:
            try:
                if aegis.config.get('use_server_logout'):
                    self.validate_member_auth_ck()
                else:
                    self._member_id = int(ck)
                return self._member_id
            except Exception as ex:
                logging.exception(ex)
                self.del_current_user()
                return None

    def set_current_user(self, member_id, member_auth_id=None, magic_token=None, get_auth_fn=aegis.model.Member.get_auth):
        cookie_val = int(member_id)
        if member_auth_id and magic_token:
            cookie_val = '%s|%s|%s' % (member_id, member_auth_id, magic_token)
        self.cookie_set('auth', cookie_val)
        self.tmpl['member'] = get_auth_fn(member_id)

    def get_current_user(self, get_auth_fn=aegis.model.Member.get_auth):
        if not aegis.database.pgsql_available and not aegis.database.mysql_available:
            return None
        if self.tmpl.get('member'):
            return self.tmpl['member']
        self.tmpl['member'] = get_auth_fn(self.get_member_id())
        return self.tmpl['member']

    def get_member_email(self, get_auth_fn=aegis.model.Member.get_auth):
        if not aegis.database.pgsql_available and not aegis.database.mysql_available:
            return None
        if 'member' not in self.tmpl:
            self.get_current_user(get_auth_fn=get_auth_fn)
        if self.tmpl['member'] and self.tmpl['member'].get('email'):
            return self.tmpl['member']['email']['email']
        logging.error("No email for this member. Does get_member_email() need to be overridden in a subclass? Is self.get_current_user() overridden in a subclass?")

    def del_current_user(self):
        # check if member_auth record exists, if so delete it, but don't explode if it doesn't match
        try:
            self.validate_member_auth_ck()
        except Exception as ex:
            logging.exception(ex)
            logging.error("This *should* be an unusual case, when cookies aren't matching. Cookies will be cleared now.")
        if aegis.config.get('use_server_logout') and hasattr(self, '_member_auth'):
            self._member_auth.revoke()
        self.cookie_clear('auth')
        self.tmpl['logged_out'] = True

    def email_link_auth(self, email_link_id, token, email_type=None):
        if not aegis.stdlib.validate_token(email_link_id, token):
            return {'error_message': "Invalid Parameters"}
        # Fetch Email Link and do sanity check
        email_link = aegis.model.EmailLink.get_id_token(email_link_id, token)
        if not email_link:
            return {'error_message': "No Magic Link"}
        if email_link['delete_dttm'] or email_link['access_dttm']:
            return {'error_message': "Already Accessed"}
        # If email_type is present, checks that the token is of the same email_type
        if email_type:
            email_tracking = aegis.model.EmailTracking.get_id(email_link['email_tracking_id'])
            if email_type['email_type_id'] != email_tracking['email_type_id']:
                return {'error_message': "Wrong Email Type"}
        # Mark email accessed and fetch it back to be more atomic and mitigate race conditions
        email_link.mark_accessed()
        email_link = aegis.model.EmailLink.get_id_token(email_link_id, token)
        # Link expires 15m after it was sent
        time_diff = email_link['access_dttm'] - email_link['create_dttm']
        if time_diff.seconds > 15*60:
            return {'error_message': "Magic Link Expired"}
        return email_link

    def is_super_admin(self):
        if not self.get_current_user():
            return False
        super_admins = aegis.config.get('super_admins')
        if super_admins and self.get_member_email() in super_admins:
            return True

    @staticmethod
    def auth_admin():
        """ Require user to be both logged-in and a super admin, or 403. """
        def call_wrapper(func):
            def authorize(self, *args, **kwargs):
                if not self.is_super_admin():
                    raise tornado.web.HTTPError(403)
                return func(self, *args, **kwargs)
            return authorize
        return call_wrapper

    # Instead of tornado.web.authenticated sending users to a login url, only send a 403
    @staticmethod
    def auth_required(method):
        def wrapper(self, *args, **kwargs):
            if not self.current_user:
                raise tornado.web.HTTPError(403)
            return method(self, *args, **kwargs)
        return wrapper


class JsonRestApi(AegisHandler):
    def check_xsrf_cookie(self): pass

    def __init__(self, *args, **kwargs):
        super(JsonRestApi, self).__init__(*args, **kwargs)
        self.debug = False

    def prepare(self):
        super(JsonRestApi, self).prepare()
        if aegis.config.get('api_token_header'):
            api_token_value = self.request.headers.get(options.api_token_header)
            if not api_token_value or api_token_value != options.api_token_value:
                raise tornado.web.HTTPError(401, 'Wrong API Token')
        else:
            logging.error("Set options.api_token_header and options.api_token_value to enforce basic API Keys from clients")
        self.json_req = self.json_unpack()
        self.json_resp = {}

    def _handle_request_exception(self, e):
        super(JsonRestApi, self)._handle_request_exception(e)
        if hasattr(self.request, 'connection') and not self.request.connection.stream.closed():
            self.json_response({'error': "Unknown error, we're looking into it"})
        logging.exception(e)
        logging.error(e)

    @staticmethod
    def json_authenticated(method):
        def wrapper(self, *args, **kwargs):
            if not self.current_user:
                return self.general_error('Must be logged in to do this', 'not_logged_in', 403)
            return method(self, *args, **kwargs)
        return wrapper

    def json_unpack(self):
        content_type = self.request.headers.get('Content-Type')
        if self.request.body and content_type and content_type.startswith('application/json'):
            try:
                json_req = json.loads(self.request.body.decode("utf-8"))
                return json_req or {}
            except json.decoder.JSONDecodeError:
                #return None  ??
                raise tornado.web.HTTPError(401, 'Bad JSON Value')
        else:
            return dict(self.request.arguments)

    def json_debug(self, debug=True):
        if options.env == 'prod':
            return False
        self.debug = debug
        if self.debug:
            self.logw(self.request, "REQ")
            self.logw(self.request.headers, "REQ HEADERS")
            self.logw(self.request.args, "ARGS")
            self.logw(self.json_req, "JSON REQ")

    def json_response(self, data, debug=False, status=200, snake_to_camel=False):
        self.set_header("Content-Type", 'application/json')
        self.set_status(status)
        if snake_to_camel:
            data = copy.deepcopy(data)
            aegis.stdlib.json_snake_to_camel(data)
        data['handler'] = self.tmpl['request_name']
        json_resp = json.dumps(data, cls=aegis.stdlib.DateTimeEncoder)
        if debug or self.debug:
            logging.warning("=== JSON RESPONSE ===")
            # Limit length of a single log line
            if len(str(data)) < 50000:
                self.logw(data, "RESPONSE DATA")
            else:
                self.logw(str(data)[:50000], "RESPONSE DATA - TOO LONG TO LOG")
            headers = []
            for (k,v) in sorted(self._headers.get_all()):
                headers.append('%s: %s' % (k,v))
            self.logw(headers, "HEADERS")
            cookies = []
            if hasattr(self, "_new_cookie"):
                for cookie in self._new_cookie.values():
                    cookies.append("Set-Cookie: %s" % cookie.OutputString(None))
            self.logw(cookies, "COOKIES")
            self.logw(json_resp, "JSON RESPONSE")
        self.json_length = len(zlib.compress(json_resp.encode("utf-8")))
        self.write(json_resp + '\n')
        self.finish()

    def json_error(self, field, error_message, error_code):
        self.json_resp.setdefault('errors', []).append({'field': field, 'error_message': error_message, 'error_code': error_code})

    def general_error(self, error_message, error_code, status=200):
        return self.json_response({'errors': [{'field': 'general', 'error_message': error_message, 'error_code': error_code}]}, status=status)

    def write_error(self, status_code, **kwargs):
        """ Overrides tornado.web.RequestHandler """
        if options.app_debug:
            exc_info = kwargs.get('exc_info')
            tb = ' '.join(traceback.format_tb(exc_info[2]))
            resp = json.dumps({'exception': tb})
        else:
            if status_code == 403:
                resp = "403 Forbidden"
            else:
                resp = json.dumps({'error': 'Sorry, something went wrong :-|'})
        self.write(resp + '\n')
        self.finish()


### Overall Application Architecture
class AegisApplication():
    def __init__(self, **kwargs):
        settings = dict(
            cookie_secret=options.cookie_secret,
            xsrf_cookies=True,
            login_url='/login',
            debug=options.app_debug
        )
        settings.update(kwargs)
        if 'static_path' in options:
            settings['static_path'] = options.static_path
        if 'static_url_prefix' in options:
            settings['static_url_prefix'] = options.static_url_prefix
        return settings

    def log_request(self, handler):
        """ From: https://github.com/tornadoweb/tornado/blob/8afac1f805de738ccd0f58618b84b0a5f90dd346/tornado/web.py#L2114
        Writes a completed HTTP request to the logs. By default writes to the python root logger.  To change this behavior either:
        subclass Application and override this method, or pass a function in the application settings dictionary as ``log_function``.
        """
        if "log_function" in self.settings:
            self.settings["log_function"](handler)
            return
        if handler.get_status() < 400:
            log_method = tornado.log.access_log.info
        elif handler.get_status() < 500:
            log_method = tornado.log.access_log.warning
        else:
            log_method = tornado.log.access_log.error
        # Main part of the response
        host = handler.request.host.split(':')[0]
        extra_debug = ''
        user_id = None
        if hasattr(handler, 'tmpl'):
            user_id = handler.tmpl.get('user', {}).get('user_id')
            extra_debug = '| uid: %s | mid: %s' % (user_id or '-', handler.get_member_id() or '-')
            if hasattr(handler, 'json_length'):
                extra_debug += ' | kb: %4.2f' % (handler.json_length / 1024.0)
            extra_debug = aegis.stdlib.cstr(extra_debug, 'yellow')
            if handler.user_is_robot():
                extra_debug += aegis.stdlib.cstr('   BOT', 'blue')
        # Timing
        request_t_ms = handler.request.request_time() * 1000   # Use tornado's from start of __init__ to end of finish() as a reference
        timers = None
        if hasattr(handler, 'timer_obj'):
            timers = handler.timer_obj._timers
        log_method("%s %d %s %.2fms %s", host, handler.get_status(), handler._request_summary(), request_t_ms, extra_debug)
        # If request takes over options.slow_req_ms we can give some extra debug output
        slow_req_ms = aegis.config.get('slow_req_ms') or 250
        if request_t_ms > slow_req_ms and timers:
            net_t_ms = timers.get('_network_exec_s', 0) * 1000
            db_t_ms = timers.get('_database_exec_s', 0) * 1000
            cpu_t_ms = request_t_ms - net_t_ms - db_t_ms
            init_t_ms = timers.get('_init_exec_s', 0) * 1000
            prepare_t_ms = timers.get('_prepare_exec_s', 0) * 1000
            render_t_ms = timers.get('_render_exec_s', 0) * 1000
            finish_t_ms = timers.get('_finish_exec_s', 0) * 1000
            handler_t_ms = request_t_ms - init_t_ms - prepare_t_ms - render_t_ms - finish_t_ms
            msg = "Req Time: %.3fms  |  %.3fms cpu  %.3fms db  %.3fms net  |  %.3fms init  %.3fms prepare  %.3fms handler   %.3fms render  %.3fms finish"
            msg = msg % (request_t_ms, cpu_t_ms, db_t_ms, net_t_ms, init_t_ms, prepare_t_ms, handler_t_ms, render_t_ms, finish_t_ms)
            tornado.log.access_log.warning(msg)



def sig_handler(sig, frame):
    io_loop = tornado.ioloop.IOLoop.instance()
    def stop_loop():
        if len(asyncio.Task.all_tasks(io_loop)) == 0:
            io_loop.stop()
        else:
            io_loop.call_later(1, stop_loop)
    io_loop.add_callback_from_signal(stop_loop)


class WebApplication(AegisApplication, tornado.web.Application):
    def __init__(self, **kwargs):
        settings = AegisApplication.__init__(self, **kwargs)
        tornado.web.Application.__init__(self, **settings)

    @staticmethod
    def start(application):
        host = options.host
        port = options.port
        http_server = tornado.httpserver.HTTPServer(application, xheaders=True, no_keep_alive=True)
        logging.info('listening on %s:%s' % (host, port))
        if host:
            http_server.listen(port, address=host)
        else:
            http_server.listen(port)  # bind all (0.0.0.0:*)
        tornado.ioloop.IOLoop.instance().start()

    @staticmethod
    def start_asyncio(application):
        host = options.host
        port = options.port
        tornado.platform.asyncio.AsyncIOMainLoop().install()
        http_server = tornado.httpserver.HTTPServer(application, xheaders=True, no_keep_alive=True)
        logging.info('listening on %s:%s' % (host, port))
        if host:
            http_server.bind(port, address=host)
        else:
            http_server.bind(port)  # bind all (0.0.0.0:*)
        signal.signal(signal.SIGTERM, functools.partial(sig_handler))
        signal.signal(signal.SIGINT, functools.partial(sig_handler))
        http_server.start()

### Aegis Web Admin


class AegisWeb(AegisHandler):
    def prepare(self):
        super(AegisWeb, self).prepare()
        self.tmpl['page_title'] = self.tmpl['request_name'].split('.')[0].replace('Aegis', '')
        self.tmpl['home_link'] = '/admin'
        self.tmpl['aegis_dir'] = aegis.config.aegis_dir()
        self.tmpl['template_dir'] = os.path.join(self.tmpl['aegis_dir'], 'templates')

    def get_template_path(self):
        return self.tmpl.get('template_dir')


class AegisHome(AegisWeb):
    @tornado.web.authenticated    # Could do something like @aegis.webapp.admin_only which also sends for login but then rejects if not admin
    def get(self, *args):
        self.enforce_admin()
        return self.render_path("index.html", **self.tmpl)


class AegisHydraForm(AegisWeb):
    @tornado.web.authenticated
    def get(self, hydra_type_id=None, *args):
        self.enforce_admin()
        self.tmpl['page_title'] = 'Hydra'
        self.tmpl['home_link'] = '/admin/hydra'
        self.tmpl['errors'] = {}
        hydra_type_id = aegis.stdlib.validate_int(hydra_type_id)
        if hydra_type_id:
            self.tmpl['hydra_type'] = aegis.model.HydraType.get_id(hydra_type_id)
        else:
            self.tmpl['hydra_type'] = {}
        self.tmpl['home_link'] = '/admin/hydra'
        return self.render_path("hydra_form.html", **self.tmpl)

    @tornado.web.authenticated
    def post(self, hydra_type_id=None, *args):
        self.enforce_admin()
        # Validate Input
        self.tmpl['errors'] = {}
        hydra_type = {}
        hydra_type['hydra_type_name'] = self.request.args.get('hydra_type_name')
        hydra_type['hydra_type_desc'] = self.request.args.get('hydra_type_desc')
        hydra_type['priority_ndx'] = aegis.stdlib.validate_int(self.request.args.get('priority_ndx'))
        hydra_type['next_run_sql'] = self.request.args.get('next_run_sql')
        hydra_type['run_host'] = self.request.args.get('run_host')
        hydra_type['run_env'] = self.request.args.get('run_env')
        self.tmpl['hydra_type'] = hydra_type
        if not hydra_type['hydra_type_name']:
            self.tmpl['errors']['hydra_type_name'] = '** required (string)'
        if not hydra_type['priority_ndx']:
            self.tmpl['errors']['priority_ndx'] = '** required (integer)'
        if self.tmpl['errors']:
            return self.render_path("hydra_form.html", **self.tmpl)
        # Run against database and send back to Hydra main
        hydra_type_id = aegis.stdlib.validate_int(hydra_type_id)
        if hydra_type_id:
            where = {'hydra_type_id': hydra_type_id}
            aegis.model.HydraType.update_columns(hydra_type, where)
        else:
            hydra_type_id = aegis.model.HydraType.insert_columns(**hydra_type)
            hydra_type_row = aegis.model.HydraType.get_id(hydra_type_id)
            hydra_type_row.set_status('paused')
        return self.redirect('/admin/hydra')


class AegisHydra(AegisWeb):
    @tornado.web.authenticated
    def get(self, *args):
        self.enforce_admin()
        self.tmpl['hydra_types'] = aegis.model.HydraType.scan()
        self.tmpl['home_link'] = '/admin/hydra'
        return self.render_path("hydra.html", **self.tmpl)

    @tornado.web.authenticated
    def post(self, *args):
        self.enforce_admin()
        pause_ids = [aegis.stdlib.validate_int(k.replace('pause_', '')) for k in self.request.args.keys() if k.startswith('pause_')]
        unpause_ids = [aegis.stdlib.validate_int(k.replace('unpause_', '')) for k in self.request.args.keys() if k.startswith('unpause_')]
        run_ids = [aegis.stdlib.validate_int(k.replace('run_', '')) for k in self.request.args.keys() if k.startswith('run_')]

        # Do Pause
        if pause_ids:
            hydra_type = aegis.model.HydraType.get_id(pause_ids[0])
            self.logw(hydra_type, "HYDRA TYPE")
            hydra_type.set_status('paused')

        # Do Unpause
        if unpause_ids:
            hydra_type = aegis.model.HydraType.get_id(unpause_ids[0])
            self.logw(hydra_type, "HYDRA TYPE")
            hydra_type.set_status('live')

        # Do Run --- hooks over to batch!
        if run_ids:
            hydra_type = aegis.model.HydraType.get_id(run_ids[0])
            self.logw(hydra_type, "HYDRA TYPE")
            hydra_type.run_now()

        return self.redirect(self.request.uri)


class AegisHydraQueue(AegisWeb):
    @tornado.web.authenticated
    def get(self, *args):
        self.enforce_admin()
        self.tmpl['page_title'] = 'Hydra'
        self.tmpl['home_link'] = '/admin/hydra'
        self.tmpl['hydra_queues'] = aegis.model.HydraQueue.scan()
        self.tmpl['queue_cnt'] = aegis.model.HydraQueue.count_live()
        return self.render_path("hydra_queue.html", **self.tmpl)

    @tornado.web.authenticated
    def post(self, *args):
        self.enforce_admin()
        run_ids = [aegis.stdlib.validate_int(k.replace('run_', '')) for k in self.request.args.keys() if k.startswith('run_')]
        if run_ids:
            hydra_queue = aegis.model.HydraQueue.get_id(run_ids[0])
            if hydra_queue:
                self.logw(hydra_queue['hydra_queue_id'], "RUN NOW HYDRA_QUEUE_ID")
                hydra_queue.run_now()
        return self.redirect('/admin/hydra/queue')


class AegisReportForm(AegisWeb):

    def validate_report_type(self, report_type_id):
        report_type_id = aegis.stdlib.validate_int(report_type_id)
        if report_type_id:
            self.tmpl['report_type'] = aegis.model.ReportType.get_id(report_type_id)
        else:
            self.tmpl['report_type'] = {}

    def validate_input(self):
        self.tmpl['errors'] = {}
        self.columns = {}
        self.columns['report_type_name'] = self.request.args.get('report_type_name')
        if not self.columns['report_type_name']:
            self.tmpl['errors']['report_type_name'] = 'Report Name Required'
        self.columns['report_sql'] = self.request.args.get('report_sql')
        if not self.columns['report_sql']:
            self.tmpl['errors']['report_sql'] = 'Report SQL Required'

    @tornado.web.authenticated
    def get(self, report_type_id=None, *args):
        self.enforce_admin()
        self.tmpl['errors'] = {}
        self.validate_report_type(report_type_id)
        return self.screen()

    @tornado.web.authenticated
    def post(self, report_type_id=None, *args):
        self.enforce_admin()
        self.validate_report_type(report_type_id)
        self.validate_input()
        if self.tmpl['errors']:
            return self.screen()
        # Set which schema the report runs against
        report_schema = self.request.args.get('report_schema')
        if report_schema and report_schema in aegis.database.dbconns.databases.keys():
            self.columns['report_schema'] = report_schema
        # Run against database and send back to Report main
        report_type_id = aegis.stdlib.validate_int(report_type_id)
        try:
            if report_type_id:
                where = {'report_type_id': report_type_id}
                aegis.model.ReportType.update_columns(self.columns, where)
            else:
                report_type_id = aegis.model.ReportType.insert_columns(**self.columns)
        except Exception as ex:
            logging.exception(ex)
            sql_error = [str(arg) for arg in ex.args]
            self.tmpl['errors']['sql_error'] = ': '.join(sql_error)
            return self.screen()
        return self.redirect('/aegis/report/%s' % report_type_id)

    def screen(self):
        self.tmpl['schemas'] = []
        if aegis.database.pgsql_available and aegis.database.mysql_available:
            self.tmpl['schemas'] = list(aegis.database.dbconns.databases.keys())
        return self.render_path("report_form.html", **self.tmpl)


class AegisReport(AegisWeb):
    @tornado.web.authenticated
    def get(self, report_type_id=None, *args):
        self.enforce_admin()
        self.tmpl['errors'] = {}
        self.tmpl['column_names'] = []
        if report_type_id:
            self.tmpl['report'] = aegis.model.ReportType.get_id(report_type_id)
            self.tmpl['output'] = None
            self.tmpl['report_totals'] = {}
            sql = self.tmpl['report']['report_sql']
            try:
                data, column_names = aegis.model.db(self.tmpl['report'].get('report_schema')).query(sql, return_column_names=True)
                for row in data:
                    for column_name, value in row.items():
                        if type(value) is int:
                            colname = aegis.stdlib.snake_to_camel(column_name, upper=True, space=True)
                            self.tmpl['report_totals'].setdefault(colname, 0)
                            self.tmpl['report_totals'][colname] += value
                data = copy.deepcopy(data)
                aegis.stdlib.json_snake_to_camel(data, upper=True, space=True, debug=False)
                self.tmpl['num_rows'] = len(data)
                self.tmpl['output'] = data
                for column_name in column_names:
                    self.tmpl['column_names'].append(aegis.stdlib.snake_to_camel(column_name, upper=True, space=True))
            except Exception as ex:
                logging.exception(ex)
                sql_error = [str(arg) for arg in ex.args]
                self.tmpl['errors']['sql_error'] = ': '.join(sql_error)
            self.tmpl['report'] = aegis.model.ReportType.get_id(report_type_id)
            return self.render_path("report.html", **self.tmpl)
        else:
            self.tmpl['reports'] = aegis.model.ReportType.scan()
            return self.render_path("reports.html", **self.tmpl)


class AegisBuild(AegisWeb):
    @tornado.web.authenticated
    def get(self, *args):
        self.enforce_admin()
        self.tmpl['builds'] = [b for b in aegis.model.Build.scan() if (not b['delete_dttm'] and b['build_target'] != 'admin')]
        self.tmpl['home_link'] = '/admin/build'
        env = aegis.config.get('env')
        if env.endswith('-admin'):
            env = env.rsplit('-', maxsplit=1)[0]
        self.tmpl['live_build'] = aegis.model.Build.get_live_build(env)
        return self.render_path("build.html", **self.tmpl)

    @tornado.web.authenticated
    def post(self, *args):
        self.tmpl['build_step'] = self.request.args.get('build_step', 'build')
        self.enforce_admin()
        # DEPLOY
        build_keys = [k for k in self.request.args.keys() if k.startswith('deploy_')]
        if build_keys:
            build_id = [aegis.stdlib.validate_int(k.replace('deploy_', '')) for k in build_keys][0]
            if build_id:
                # Set output to '' so the web can see that it's started
                build_row = aegis.model.Build.get_id(build_id)
                build_row.set_output('deploy', '')
                hydra_type = aegis.model.HydraType.get_name('deploy_build')
                # Put an item on the work queue to signal each host to deploy
                for deploy_host in options.deploy_hosts:
                    hydra_queue = {'hydra_type_id': hydra_type['hydra_type_id'], 'priority_ndx': hydra_type['priority_ndx'], 'work_dttm': aegis.database.Literal("NOW()"),
                                   'work_host': deploy_host, 'work_env': aegis.config.get('env')}
                    work_data = {'build_id': build_id, 'user': self.get_member_email()}
                    hydra_queue['work_data'] = json.dumps(work_data, cls=aegis.stdlib.DateTimeEncoder)
                    hydra_queue_id = aegis.model.HydraQueue.insert_columns(**hydra_queue)
                return self.redirect('/admin/build')
        # REVERT
        revert_keys = [k for k in self.request.args.keys() if k.startswith('revert_')]
        if revert_keys:
            build_id = [aegis.stdlib.validate_int(k.replace('revert_', '')) for k in revert_keys][0]
            if build_id:
                # Set output to '' so the web can see that it's started
                build_row = aegis.model.Build.get_id(build_id)
                build_row.set_output('revert', '')
                hydra_type = aegis.model.HydraType.get_name('revert_build')
                # Put an item on the work queue to signal each host to deploy
                for deploy_host in options.deploy_hosts:
                    hydra_queue = {'hydra_type_id': hydra_type['hydra_type_id'], 'priority_ndx': hydra_type['priority_ndx'], 'work_dttm': aegis.database.Literal("NOW()"),
                                   'work_host': deploy_host, 'work_env': aegis.config.get('env')}
                    work_data = {'build_id': build_id, 'user': self.get_member_email()}
                    hydra_queue['work_data'] = json.dumps(work_data, cls=aegis.stdlib.DateTimeEncoder)
                    hydra_queue_id = aegis.model.HydraQueue.insert_columns(**hydra_queue)
                return self.redirect('/admin/build')
        # DELETE
        delete_keys = [k for k in self.request.args.keys() if k.startswith('delete_')]
        if delete_keys:
            build_id = [aegis.stdlib.validate_int(k.replace('delete_', '')) for k in delete_keys][0]
            if build_id:
                build = aegis.model.Build.get_id(build_id)
                build.set_soft_deleted()
                return self.redirect('/admin/build')


class AegisBuildForm(AegisWeb):
    @tornado.web.authenticated
    def get(self, *args):
        self.enforce_admin()
        self.tmpl['page_title'] = 'Build'
        self.tmpl['errors'] = {}
        self.tmpl['build'] = {}
        self.tmpl['build_step'] = self.request.args.get('build_step', 'build')
        self.tmpl['home_link'] = '/admin/build'
        return self.render_path("build_form.html", **self.tmpl)

    @tornado.web.authenticated
    def post(self, *args):
        self.enforce_admin()
        # Validate Input
        self.tmpl['errors'] = {}
        self.tmpl['build'] = build = {}
        build['branch'] = self.request.args.get('branch')
        build['revision'] = self.request.args.get('revision')
        if not build['branch']:
            self.tmpl['errors']['branch'] = '** required (string)'
        if self.tmpl['errors']:
            return self.render_path("build_form.html", **self.tmpl)
        if not build['revision']:
            build['revision'] = 'HEAD'
        aegis.stdlib.logw(aegis.config.get('env'), "RUNNING ENV")
        build['env'] = aegis.config.get('env')
        if aegis.config.get('env').endswith('-admin'):
            build['env'] = aegis.config.get('env').rsplit('-', maxsplit=1)[0]
        aegis.stdlib.logw(build['env'], "SET BUILD ENV FROM PROCESS ENV")
        build['build_target'] = 'application'

        # Create build row and add it to run on Hydra
        build_id = aegis.model.Build.insert_columns(**build)
        hydra_type = aegis.model.HydraType.get_name('build_build')
        hydra_queue = {'hydra_type_id': hydra_type['hydra_type_id'], 'priority_ndx': hydra_type['priority_ndx'], 'work_dttm': aegis.database.Literal("NOW()"),
                       'work_host': aegis.config.get('build_host'), 'work_env': aegis.config.get('env')}
        work_data = {'build_id': build_id, 'user': self.get_member_email()}
        hydra_queue['work_data'] = json.dumps(work_data, cls=aegis.stdlib.DateTimeEncoder)
        hydra_queue_id = aegis.model.HydraQueue.insert_columns(**hydra_queue)
        self.redirect('/admin/build')


class AegisBuildView(AegisWeb):
    @tornado.web.authenticated
    def get(self, build_id, *args):
        self.tmpl['page_title'] = 'Build'
        self.tmpl['home_link'] = '/admin/build'
        self.enforce_admin()
        self.tmpl['errors'] = {}
        build_id = aegis.stdlib.validate_int(build_id)
        if build_id:
            self.tmpl['build'] = aegis.model.Build.get_id(build_id)
        else:
            self.tmpl['build'] = {}
        self.tmpl['build_step'] = self.request.args.get('build_step', 'build')
        return self.render_path("build_view.html", **self.tmpl)

    @tornado.web.authenticated
    def post(self, build_id, *args):
        self.enforce_admin()
        # Validate Input
        self.tmpl['errors'] = {}
        self.tmpl['build'] = build = {}
        build['branch'] = self.request.args.get('branch')
        build['revision'] = self.request.args.get('revision')
        if not build['branch']:
            self.tmpl['errors']['branch'] = '** required (string)'
        if not build['revision']:
            build['revision'] = 'HEAD'
        if self.tmpl['errors']:
            return self.render_path("build_form.html", **self.tmpl)
        build['env'] = aegis.config.get('env')
        # Create build row and add it to run on Hydra
        build_id = aegis.model.Build.insert_columns(**build)
        hydra_type = aegis.model.HydraType.get_name('build_build')
        hydra_queue = {'hydra_type_id': hydra_type['hydra_type_id'], 'priority_ndx': hydra_type['priority_ndx'], 'work_dttm': aegis.database.Literal("NOW()"),
                       'work_host': aegis.config.get('build_host'), 'work_env': aegis.config.get('env')}
        work_data = {'build_id': build_id, 'user': self.get_member_email()}
        hydra_queue['work_data'] = json.dumps(work_data, cls=aegis.stdlib.DateTimeEncoder)
        hydra_queue_id = aegis.model.HydraQueue.insert_columns(**hydra_queue)
        self.redirect('/admin/build')


class AegisBuildConfirm(AegisWeb):
    @tornado.web.authenticated
    def get(self, build_id, build_step, *args):
        self.enforce_admin()
        self.tmpl['build_row'] = aegis.model.Build.get_id(aegis.stdlib.validate_int(build_id))
        self.tmpl['build_step'] = build_step
        self.tmpl['errors'] = {}
        return self.screen()

    @tornado.web.authenticated
    def post(self, build_id, build_step, *args):
        self.enforce_admin()
        self.tmpl['build_row'] = aegis.model.Build.get_id(aegis.stdlib.validate_int(build_id))
        self.tmpl['build_step'] = build_step
        self.tmpl['errors'] = {}
        # Validate Input
        message = self.request.args.get('message')
        if not message:
            self.tmpl['errors']['message'] = '** required (string)'
            return self.screen()
        # Save the user message and start the deploy/revert
        self.tmpl['build_row'].set_message(message, build_step)
        self.tmpl['build_row'] = aegis.model.Build.get_id(aegis.stdlib.validate_int(build_id))
        if build_step == 'deploy':
            aegis.build.Build.start_deploy(self.tmpl['build_row'], self.get_member_email())
        elif build_step == 'revert':
            aegis.build.Build.start_revert(self.tmpl['build_row'], self.get_member_email())
        # Set output to '' so the web can see that it's started
        self.tmpl['build_row'] = aegis.model.Build.get_id(aegis.stdlib.validate_int(build_id))
        self.tmpl['build_row'].set_output(build_step, '')
        hydra_type = aegis.model.HydraType.get_name('%s_build' % build_step)
        # Put an item on the work queue to signal each host to deploy
        for deploy_host in options.deploy_hosts:
            hydra_queue = {'hydra_type_id': hydra_type['hydra_type_id'], 'priority_ndx': hydra_type['priority_ndx'], 'work_dttm': aegis.database.Literal("NOW()"),
                           'work_host': deploy_host, 'work_env': aegis.config.get('env')}
            work_data = {'build_id': build_id, 'user': self.get_member_email()}
            hydra_queue['work_data'] = json.dumps(work_data, cls=aegis.stdlib.DateTimeEncoder)
            hydra_queue_id = aegis.model.HydraQueue.insert_columns(**hydra_queue)
        return self.redirect('/admin/build')

    def screen(self):
        self.tmpl['home_link'] = '/admin/build'
        self.tmpl['page_title'] = 'Build'
        self.tmpl['commits'] = aegis.build.Build.commit_diff(self.tmpl['build_row'])
        self.tmpl['live_build'] = aegis.model.Build.get_live_build(self.tmpl['build_row']['env'])
        return self.render_path("build_confirm.html", **self.tmpl)


handler_urls = [
    (r'^/admin/build/(\d+)/(deploy|revert)\W*$', AegisBuildConfirm),
    (r'^/admin/build/(\d+)\W*$', AegisBuildView),
    (r'^/admin/build/add\W*$', AegisBuildForm),
    (r'^/admin/build\W*$', AegisBuild),
    (r'^/admin/hydra/queue\W*$', AegisHydraQueue),
    (r'^/admin/hydra/add\W*$', AegisHydraForm),
    (r'^/admin/hydra/(\d+)\W*$', AegisHydraForm),
    (r'^/admin/hydra\W*$', AegisHydra),
    (r'^/admin/report/form/(\d+)\W*$', AegisReportForm),
    (r'^/admin/report/form\W*$', AegisReportForm),
    (r'^/admin/report/(\d+)\W*$', AegisReport),
    (r'^/admin/report\W*$', AegisReport),
    (r'^/admin\W*$', AegisHome),
]
