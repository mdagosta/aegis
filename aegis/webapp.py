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
import user_agents

# Project Imports
import aegis.stdlib
import aegis.model
import aegis.config
import aegis.database
import config


class AegisHandler(tornado.web.RequestHandler):
    def __init__(self, *args, **kwargs):
        super(AegisHandler, self).__init__(*args, **kwargs)
        self.tmpl = {}
        self.tmpl['logw'] = self.logw = aegis.stdlib.logw
        hostname = self.request.host.split(':')[0]
        self.tmpl['host'] = hostname
        # Don't allow direct IP address in the Host header
        if aegis.stdlib.validate_ip_address(self.tmpl['host']):
            logging.warning("Disallow IP Address in Host Header: %s", self.tmpl['host'])
            raise tornado.web.HTTPError(400)
        # Implement *.domain.com to still work on domain.com
        host_split = hostname.split('.')
        valid_subdomains = aegis.config.get('valid_subdomains')
        if len(host_split) > 2 and valid_subdomains and host_split[0] not in valid_subdomains:
            self.tmpl['host'] = '.'.join(host_split[1:])
        # Ignore crazy hostnames. Only use the ones we have specified.
        if self.tmpl['host'] not in config.hostnames.keys():
            logging.warning("Ignore crazy hostname: %s", self.tmpl['host'])
            raise tornado.web.HTTPError(404)
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
        self.tmpl['get_user_id'] = self.get_user_id
        self.tmpl['get_member_id'] = self.get_member_id
        self.tmpl['get_member_email'] = self.get_member_email
        self.models = {}
        self.models['UserAgent'] = aegis.model.UserAgent
        self.models['User'] = aegis.model.User

    def prepare(self):
        self.set_header('Cache-Control', 'no-cache, no-store')
        self.set_header('Pragma', 'no-cache')
        self.set_header('Expires', 'Fri, 21 Dec 2012 03:08:13 GMT')
        self.tmpl['request_name'] = self.page_name = '%s.%s' % (self.__class__.__name__, self.request.method)
        self.tmpl['next_url'] = self.get_next_url()
        self.request.args = dict([(key, self.get_argument(key)) for key, val in self.request.arguments.items()])
        if aegis.config.get('pg_database') or aegis.config.get('mysql_database'):
            self.setup_user()
        super(AegisHandler, self).prepare()

    def finish(self, chunk=None):
        auth_ck = self.cookie_get('auth')
        logged_out = (self.tmpl.get('logged_out') == True)
        if auth_ck and not logged_out:
            self.cookie_set('auth', auth_ck)
        if 'session_ck' in self.tmpl:
            if self.tmpl.get('session_ck'):
                self.cookie_set('session', self.tmpl['session_ck'])
            else:
                self.cookie_clear('session')
        super(AegisHandler, self).finish(chunk)

    def setup_user(self):
        # Set up user-cookie tracking system, based on user-agent
        self.tmpl['user'] = {}
        if not self.tmpl['user_agent']:
            self.tmpl['user_agent'] = 'NULL USER AGENT'
        self.tmpl['user_agent_obj'] = user_agents.parse(self.tmpl['user_agent'])
        user_agent = self.models['UserAgent'].set_user_agent(self.tmpl['user_agent'])
        user_agents_bot = self.tmpl['user_agent_obj'].is_bot
        aegis_bot = aegis.stdlib.is_robot(self.tmpl["user_agent"])
        if user_agents_bot or aegis_bot:
            if user_agents_bot and aegis_bot:
                logging.warning("Duplicate robot: %s", self.tmpl['user_agent'])
            self.models['UserAgent'].set_robot_ind(user_agent['user_agent_id'], True)
            user_agent = self.models['UserAgent'].get_id(user_agent['user_agent_id'])
        # Set up all robots to use the same user_id, based on the user-agent string, and don't bother with cookies.
        # Regular users just get tagged with a user cookie matching a row.
        if user_agent['robot_ind']:
            if not user_agent['robot_user_id']:
                user_id = self.models['User'].insert(user_agent['user_agent_id'])
                self.models['UserAgent'].set_robot_user_id(user_agent['user_agent_id'], user_id)
                user_agent = self.models['UserAgent'].get_id(user_agent['user_agent_id'])
            user = self.models['User'].get_id(user_agent['robot_user_id'])
            user_ck = {}
        else:
            user_ck = self.cookie_get('user')
            if user_ck and user_ck.get('user_id'):
                user = self.models['User'].get_id(user_ck['user_id'])
                self.cookie_set('user', user_ck)
            else:
                user_id = self.models['User'].insert(user_agent['user_agent_id'])
                user = self.models['User'].get_id(user_id)
                if user_ck:
                    user_ck['user_id'] = user_id
                else:
                    user_ck = {'user_id': user_id}
                self.cookie_set('user', user_ck)
        self.tmpl['user']['user_id'] = user['user_id']

    def render(self, template_name, **kwargs):
        template_path = os.path.join(options.template_path, template_name)
        return super(AegisHandler, self).render(template_path, **kwargs)

    def render_path(self, template_name, **kwargs):
        template_path = os.path.join(self.get_template_path(), template_name)
        return super(AegisHandler, self).render(template_path, **kwargs)

    def get_template_path(self):
        return options.template_path

    def _handle_request_exception(self, ex):
        #self.logw(ex, "EX")
        #logging.exception(ex)
        if self.request.headers.get('Cookie'):
            # Remove cookie info to anonymize and make message shorter and more useful. Almost never used in debug.
            del self.request.headers['Cookie']
        # Don't post boring pseudo-errors to channels
        if isinstance(ex, tornado.web.HTTPError) and ex.status_code in [401, 403, 404, 405]:
            logging.warning("Prevent too-annoying errors from POSTing to Chat")
            super(AegisHandler, self)._handle_request_exception(ex)
            return
        # Send errors to chat hooks, based on them being configured for the environment
        header = "`[%s ENV   %s   %s   uid: %s   mid: %s]`" % (config.get_env().upper(), self.request.uri, self.tmpl['request_name'], self.get_user_id() or '-', self.get_member_id() or '-')
        template_opts = {'handler': self, 'traceback': traceback.format_exc(), 'kwargs': {}, 'header': header}
        hooks = ['alerts_chat_hook', 'debug_chat_hook']
        for hook in hooks:
            hook_url = aegis.config.get(hook)
            if hook_url:
                error_message = self.render_string("error_message.txt", **template_opts).decode('utf-8')
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
        if self.tmpl['env'] != 'prod':
            name = "%s_%s" % (self.tmpl['env'], name)
        return name

    def cookie_set(self, name, value, cookie_duration=None):
        # Session cookie is set to None duration to implement a browser session cookie
        if not cookie_duration:
            cookie_durations = aegis.config.get('cookie_durations')
            if not cookie_durations:
                cookie_durations = {'user': 3650, 'session': None, 'auth': 14}
            cookie_duration = cookie_durations[name]
        cookie_flags = {'httponly': True, 'secure': True}
        cookie_val = self.cookie_encode(value)
        self.set_secure_cookie(self.cookie_name(name), cookie_val, expires_days=cookie_duration, domain=options.hostname, **cookie_flags)

    def cookie_get(self, name, cookie_duration=None):
        # Session cookie is set to 30 since browser should expire session cookie not time-limit
        if not cookie_duration:
            cookie_durations = aegis.config.get('cookie_durations')
            if not cookie_durations:
                cookie_durations = {'user': 3650, 'session': 30, 'auth': 14}
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
        if not aegis.database.pgsql_available and not aegis.database.mysql_available:
            return None
        self.tmpl['member'] = aegis.model.Member.get_auth(self.get_member_id())
        return self.tmpl['member']

    def get_member_email(self):
        if not aegis.database.pgsql_available and not aegis.database.mysql_available:
            return None
        if 'member' not in self.tmpl:
            self.get_current_user()
        if self.tmpl['member']:
            return self.tmpl['member']['email']['email']

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

    def is_super_admin(self):
        if not self.get_current_user():
            return False
        super_admins = aegis.config.get('super_admins')
        if super_admins and self.get_member_email() in super_admins:
            return True


class JsonRestApi(AegisHandler):
    def check_xsrf_cookie(self): pass

    def __init__(self, *args, **kwargs):
        super(JsonRestApi, self).__init__(*args, **kwargs)
        self.debug = False

    def prepare(self):
        super(JsonRestApi, self).prepare()
        api_token_value = self.request.headers.get(options.api_token_header)
        if not api_token_value or api_token_value != options.api_token_value:
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
            member_id = None
            if handler.tmpl.get('member'):
                member_id = handler.tmpl['member'].get('member_id')
            extra_debug = '| uid: %s | mid: %s' % (user_id or '-', member_id or '-')
            extra_debug = aegis.stdlib.cstr(extra_debug, 'yellow')
            if handler.tmpl.get('user_agent_obj').is_bot:
                extra_debug += aegis.stdlib.cstr('   BOT', 'blue')
            if hasattr(handler, 'json_length'):
                extra_debug += '   kbytes: %4.2f' % (handler.json_length / 1024.0)
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


### Aegis Web Admin

class AegisWeb(AegisHandler):
    def prepare(self):
        super(AegisWeb, self).prepare()
        if not self.is_super_admin():
            raise tornado.web.HTTPError(403)
        self.tmpl['page_title'] = self.tmpl['request_name'].split('.')[0].replace('Aegis', '')
        self.tmpl['aegis_dir'] = aegis.config.aegis_dir()
        self.tmpl['template_dir'] = os.path.join(self.tmpl['aegis_dir'], 'templates')

    def get_template_path(self):
        return self.tmpl.get('template_dir')

class AegisHydraForm(AegisWeb):
    def get(self, hydra_type_id=None, *args):
        self.tmpl['errors'] = {}
        hydra_type_id = aegis.stdlib.validate_int(hydra_type_id)
        if hydra_type_id:
            self.tmpl['hydra_type'] = aegis.model.HydraType.get_id(hydra_type_id)
        else:
            self.tmpl['hydra_type'] = {}
        return self.render_path("hydra_form.html", **self.tmpl)

    def post(self, hydra_type_id=None, *args):
        self.logw(self.request.args, "ARGS")
        # Validate Input
        self.tmpl['errors'] = {}
        hydra_type = {}
        hydra_type['hydra_type_name'] = self.request.args.get('hydra_type_name')
        hydra_type['hydra_type_desc'] = self.request.args.get('hydra_type_desc')
        hydra_type['priority_ndx'] = aegis.stdlib.validate_int(self.request.args.get('priority_ndx'))
        hydra_type['next_run_sql'] = self.request.args.get('next_run_sql')
        if not hydra_type['priority_ndx']:
            self.tmpl['errors']['priority_ndx'] = 'Must be an integer'
        if self.tmpl['errors']:
            return self.render_path("hydra_form.html", **self.tmpl)
        # Run against database and send back to Hydra main
        hydra_type_id = aegis.stdlib.validate_int(hydra_type_id)
        if hydra_type_id:
            where = {'hydra_type_id': hydra_type_id}
            aegis.model.HydraType.update_columns(hydra_type, where)
        else:
            aegis.model.HydraType.insert_columns(**hydra_type)
        return self.redirect('/aegis/hydra')


class AegisHydra(AegisWeb):
    def get(self, *args):
        self.tmpl['hydra_types'] = aegis.model.HydraType.scan()
        return self.render_path("hydra.html", **self.tmpl)

    def post(self, *args):
        self.logw(self.request.args, "ARGS")
        pause_ids = [aegis.stdlib.validate_int(k.replace('pause_', '')) for k in self.request.args.keys() if k.startswith('pause_')]
        unpause_ids = [aegis.stdlib.validate_int(k.replace('unpause_', '')) for k in self.request.args.keys() if k.startswith('unpause_')]
        run_ids = [aegis.stdlib.validate_int(k.replace('run_', '')) for k in self.request.args.keys() if k.startswith('run_')]
        self.logw(pause_ids, "PAUSE IDS")
        self.logw(run_ids, "RUN IDS")

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


    def get(self, report_type_id=None, *args):
        self.tmpl['errors'] = {}
        self.validate_report_type(report_type_id)
        self.tmpl['schemas'] = []
        if aegis.database.pgsql_available and aegis.database.mysql_available:
            schemas = []
            self.tmpl['schemas'] = list(aegis.database.dbconns.databases.keys())
        return self.render_path("report_form.html", **self.tmpl)


    def post(self, report_type_id=None, *args):
        self.validate_report_type(report_type_id)
        self.validate_input()
        if self.tmpl['errors']:
            return self.render_path("report_form.html", **self.tmpl)
        # Set which schema the report runs against
        report_schema = self.request.args.get('report_schema')
        if report_schema and report_schema in aegis.database.dbconns.databases.keys():
            self.columns['report_schema'] = report_schema
        # Run against database and send back to Report main
        report_type_id = aegis.stdlib.validate_int(report_type_id)
        if report_type_id:
            where = {'report_type_id': report_type_id}
            aegis.model.ReportType.update_columns(self.columns, where)
        else:
            aegis.model.ReportType.insert_columns(**self.columns)
        return self.redirect('/aegis/report')


class AegisReport(AegisWeb):
    def get(self, report_type_id=None, *args):
        self.tmpl['errors'] = {}
        if report_type_id:
            self.tmpl['report'] = aegis.model.ReportType.get_id(report_type_id)
            self.tmpl['output'] = None
            sql = self.tmpl['report']['report_sql']
            try:
                self.tmpl['output'] = aegis.model.db(self.tmpl['report'].get('report_schema')).query(sql)
            except Exception as ex:
                #logging.exception(ex)
                sql_error = [str(arg) for arg in ex.args]
                self.tmpl['errors']['sql_error'] = ': '.join(sql_error)
            self.tmpl['report'] = aegis.model.ReportType.get_id(report_type_id)
            return self.render_path("report.html", **self.tmpl)
        else:
            self.tmpl['reports'] = aegis.model.ReportType.scan()
            return self.render_path("reports.html", **self.tmpl)


class AegisHome(AegisWeb):
    def get(self, *args):
        return self.render_path("index.html", **self.tmpl)


handler_urls = [
    (r'^/aegis/hydra/add\W*$', AegisHydraForm),
    (r'^/aegis/hydra/(\d+)\W*$', AegisHydraForm),
    (r'^/aegis/hydra\W*$', AegisHydra),
    (r'^/aegis/report/form/(\d+)\W*$', AegisReportForm),
    (r'^/aegis/report/form\W*$', AegisReportForm),
    (r'^/aegis/report/(\d+)\W*$', AegisReport),
    (r'^/aegis/report\W*$', AegisReport),
    (r'^/aegis\W*$', AegisHome),
]
