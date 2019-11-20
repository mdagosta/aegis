#!/usr/bin/env python3
#-*- coding: utf-8 -*-
#
# Aegis is your shield to protect you on the Brave New Web

# Python Imports
import json
import logging
import os
import sys
import traceback
import urllib

# Extern Imports
import requests
from tornado.options import options
import tornado.web
import aegis.stdlib
import aegis.model

# Project Imports
import config


class AegisHandler(tornado.web.RequestHandler):
    def __init__(self, *args, **kwargs):
        super(AegisHandler, self).__init__(*args, **kwargs)
        self.logw = aegis.stdlib.logw
        self.tmpl = {}
        self.tmpl['host'] = self.request.host
        config.apply_hostname(self.tmpl['host'])
        self.tmpl['options'] = options
        self.tmpl['program_name'] = options.program_name
        self.tmpl['app_name'] = options.app_name
        self.tmpl['env'] = config.get_env()
        self.tmpl['domain'] = options.domain
        self.tmpl['referer'] = self.request.headers.get('Referer')
        self.tmpl['user_agent'] = self.request.headers.get('User-Agent')
        self.tmpl['scheme'] = 'https://'
        self.tmpl['get_current_user'] = self.get_current_user
        self.tmpl['xsrf_token'] = self.xsrf_token
        self.tmpl['nl2br'] = aegis.stdlib.nl2br
        self.tmpl['format_integer'] = aegis.stdlib.format_integer

    def prepare(self):
        self.set_header('Cache-Control', 'no-cache')
        self.set_header('Pragma', 'no-cache')
        self.set_header('Expires', 'Fri, 21 Dec 2012 03:08:13 GMT')
        self.tmpl['request_name'] = self.page_name = '%s.%s' % (self.__class__.__name__, self.request.method)
        self.tmpl['next_url'] = self.get_next_url()
        self.request.args = dict([(key, self.get_argument(key)) for key, val in self.request.arguments.items()])
        if options.pg_database:
            self.setup_user()
        super(AegisHandler, self).prepare()

    def finish(self, chunk=None):
        auth_ck = self.cookie_get('auth')
        logged_out = self.tmpl.get('logged_out') == True
        if auth_ck and not logged_out:
            self.cookie_set('auth', auth_ck)
        super(AegisHandler, self).finish(chunk)

    def setup_user(self):
        # Set up user-cookie tracking system, based on user-agent
        self.tmpl['user'] = {}
        if not self.tmpl['user_agent']:
            self.tmpl['user_agent'] = 'NULL USER AGENT'
        user_agent = aegis.model.UserAgent.set_user_agent(self.tmpl['user_agent'])
        # Set up all robots to use the same user_id, based on the user-agent string, and don't bother with cookies.
        # Regular users just get tagged with a user cookie matching a row.
        if user_agent['robot_ind']:
            if not user_agent['robot_user_id']:
                user_id = aegis.model.User.insert(user_agent['user_agent_id'])
                aegis.model.UserAgent.set_robot_user_id(user_agent['user_agent_id'], user_id)
                user_agent = aegis.model.UserAgent.get_id(user_agent['user_agent_id'])
            user = aegis.model.User.get_id(user_agent['robot_user_id'])
            user_ck = {}
        else:
            user_ck = self.cookie_get('user')
            if user_ck and user_ck.get('user_id'):
                user = aegis.model.User.get_id(user_ck['user_id'])
                self.cookie_set('user', user_ck)
            else:
                user_id = aegis.model.User.insert(user_agent['user_agent_id'])
                user = aegis.model.User.get_id(user_id)
                if user_ck:
                    user_ck['user_id'] = user_id
                else:
                    user_ck = {'user_id': user_id}
                self.cookie_set('user', user_ck)
        self.tmpl['user']['user_id'] = user['user_id']

    def render(self, template_name, **kwargs):
        template_path = os.path.join(options.template_path, template_name)
        return super(AegisHandler, self).render(template_path, **kwargs)

    def get_template_path(self):
        return options.template_path

    def _handle_request_exception(self, ex):
        self.logw(ex, "EX")
        logging.exception(ex)
        if self.request.headers.get('Cookie'):
            del self.request.headers['Cookie']    # Remove to anonymize and make message shorter and more useful. Almost never used.
        header = "`[%s ENV   %s   %s]`" % (config.get_env().upper(), self.request.uri, self.tmpl['request_name'])
        template_opts = {'handler': self, 'traceback': traceback.format_exc(), 'kwargs': {}}
        rendered = self.render_string("error_message.txt", **template_opts).decode('utf-8')
        if isinstance(ex, tornado.web.HTTPError) and ex.status_code in [401, 403, 404, 405]:
            logging.debug("Prevent too-annoying errors from POSTing to Slack")
        else:
            requests.post(options.slack_error_hook, json={"text": rendered})
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
        if self.tmpl['env'] != 'prod':
            name = "%s_%s" % (self.tmpl['env'], name)
        return name

    def cookie_set(self, name, value):
        """ Session cookie is set to None duration to implement a browser session cookie """
        cookie_duration = {'user': 3650, 'session': None, 'auth': 14}[name]
        self.set_secure_cookie(self.cookie_name(name), self.cookie_encode(value), expires_days=cookie_duration, domain=options.hostname)

    def cookie_get(self, name):
        """ Session cookie is set to 31 since browser should expire session cookie """
        cookie_duration = {'user': 3650, 'session': 30, 'auth': 14}[name]
        return self.cookie_decode(self.get_secure_cookie(self.cookie_name(name), max_age_days=cookie_duration))

    def cookie_clear(self, name):
        self.clear_cookie(self.cookie_name(name), domain=options.hostname)


    # Authentication
    def set_current_user(self, member_id):
        self.cookie_set('auth', int(member_id))
        self.tmpl['member'] = aegis.model.Member.get_auth(member_id)

    def get_member_id(self):
        ck = self.cookie_get("auth")
        if ck:
            try:
                return int(ck)
            except Exception as ex:
                logging.exception(ex)
                self.del_current_user()
                return None
        # When not on production, if test token and test member_id are present, use that for the request.
        test_token = self.request.headers.get('Test-Token')
        test_member_id = aegis.stdlib.validate_int(self.request.headers.get('Test-Member-Id'))
        if self.tmpl['env'] != 'prod' and test_token and test_token == options.test_token and test_member_id:
            # Check member exists so we don't just explode from exhuberant testing!
            if aegis.model.Member.get_id(test_member_id):
                logging.warning("Test Mode | MemberId Override: %s", test_member_id)
                return test_member_id


    def get_current_user(self):
        if options.pg_database:
            self.tmpl['member'] = aegis.model.Member.get_auth(self.get_member_id())
            return self.tmpl['member']

    def del_current_user(self):
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


class JsonRestApi(AegisHandler):
    def check_xsrf_cookie(self): pass

    def __init__(self, *args, **kwargs):
        super(JsonRestApi, self).__init__(*args, **kwargs)
        self.debug = False

    def prepare(self):
        super(JsonRestApi, self).prepare()
        api_token = self.request.headers.get(options.api_token)
        if not api_token or api_token != options.api_key:
            raise tornado.web.HTTPError(401, 'Wrong API Token')
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
        request_time = 1000.0 * handler.request.request_time()
        host = handler.request.host.split(':')[0]
        extra_debug = ''
        user_id = None
        member_id = None
        if hasattr(handler, 'tmpl'):
            user_id = handler.tmpl.get('user', {}).get('user_id')
            extra_debug = '| uid: %s' % (user_id or '-')
            extra_debug = aegis.stdlib.cstr(extra_debug, 'yellow')
        log_method("%s %d %s %.2fms %s", host, handler.get_status(), handler._request_summary(), request_time, extra_debug)


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
