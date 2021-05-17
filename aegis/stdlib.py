#-*- coding: utf-8 -*-


# Python Imports
import calendar
import datetime
import decimal
import functools
import hashlib
import inspect
import ipaddress
import json
import logging
import os
import pprint
import random
import re
import shlex
import string
import subprocess
import time
import xml

# Extern Imports
import bcrypt
import dateutil.parser
import tornado.util


def absdir(path):
    return os.path.abspath(os.path.dirname(path))

def get_caller():
    f = inspect.currentframe()
    f = f.f_back
    f = f.f_back
    filename = f.f_code.co_filename
    module = filename.split('/')[-1].split('.')[0]
    lineno = f.f_lineno
    return "%s:%s" % (module, lineno)

def logw(var, msg=''):
    caller = get_caller()
    logging.warning('%s %s %s %s', cstr(caller, 'yellow'), msg, type(var), pprint.pformat(var))

def loge(var, msg=''):
    caller = get_caller()
    logging.error('%s %s %s %s', cstr(caller, 'red'), msg, type(var), pprint.pformat(var))

def logline(*args):
    caller = get_caller()
    msg = '%s %s' % (cstr(caller, 'yellow'), args[0])
    logging.warning(msg, *args[1:])

def shell(cmd, cwd=None, env=None):
    if type(cmd) not in (tuple, list):
        cmd = shlex.split(cmd)
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False, cwd=cwd, env=env)
    stdout, stderr = proc.communicate()
    stdout = stdout.decode('utf-8').strip()
    stderr = stderr.decode('utf-8').strip()
    return (stdout, stderr, proc.returncode)

def force_int(string):
    if type(string) in (int, int): return int(string)
    int_re = re.compile('^.*?(\d+).*?$')
    match = int_re.match(string)
    if not match: return None
    return int(match.group(1))

def md5hex(val=None, encoding=None):
    if val:
        if encoding:
            val = val.encode(encoding)
        return hashlib.md5(val).hexdigest()
    else:
        return hashlib.md5().hexdigest()

def bcrypt_salt(log_rounds=14):
    return bcrypt.gensalt(rounds=log_rounds)

def bcrypt_hashpw(password, salt):
    result = bcrypt.hashpw(password, salt.encode('utf-8'))
    return result

def bcrypt_password(password, log_rounds=14):
    if type(password) is str:
        password = password.encode('utf-8')
    salt = tornado.util.unicode_type(bcrypt.gensalt(rounds=log_rounds), 'ascii').encode('utf-8')
    return bcrypt.hashpw(password, salt)

password_len = 24
password_chars = string.ascii_letters + string.digits
def pwgen(pw_len=password_len, pw_chars=password_chars):
    pw = functools.reduce(lambda x, y: x + random.choice(pw_chars), range(pw_len), '')
    max_pw = float(pow(len(pw_chars), pw_len))
    max_pw_int = int(max_pw)
    max_pw_str = f"{max_pw_int:100,}"
    return pw, max_pw, max_pw_str

def html_unescape(val):
    return xml.sax.saxutils.unescape(val, {'&quot;': '"'})

def split_name(name):
    if not name or type(name) is not str:
        return None
    names = name.split()
    if len(names) == 1:
        return {'first_name': name, 'last_name': ''}
    else:
        first = ' '.join(name.split()[:-1])
        last = name.split()[-1]
        return {'first_name': first, 'last_name': last}

def map_items(items, key):
    return dict([(item[key], item) for item in items])


class DateTimeEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime.datetime):
            return obj.isoformat()
        elif isinstance(obj, datetime.date):
            return obj.isoformat()
        elif isinstance(obj, datetime.timedelta):
            return (datetime.datetime.min + obj).time().isoformat()
        elif isinstance(obj, decimal.Decimal):
            return float(obj)
        else:
            return super(DateTimeEncoder, self).default(obj)


# Tools for converting 'snake_case' to 'lowerCamelCase' 'UpperCamelCase' and 'Space Camel Case'. Adapted from: https://stackoverflow.com/a/19053800
def snake_to_camel(snake_str, upper=False, space=False):
    components = snake_str.split('_')
    if upper:
        join_char = ''
        if space:
            join_char = ' '
        # Capitalize the first letter of each component, using title(), then join them together.
        return join_char.join(x.title() for x in components)
    else:
        # Capitalize the first letter of each component except the first one, using title(), then join them together.
        return components[0] + ''.join(x.title() for x in components[1:])

def camel_to_snake(camelStr):
      mid_str = re.sub('(.)([A-Z][a-z]+)', r'\1_\2', camelStr)
      return re.sub('([a-z0-9])([A-Z])', r'\1_\2', mid_str).lower()

# This rewrites the key in-place. Make a copy.deepcopy() before calling this!
def json_snake_to_camel(json_obj, upper=False, space=False, debug=False):
    mro = inspect.getmro(json_obj.__class__)
    if dict in mro:
        # Since the json_obj is changing in place, grab the keys to iterate up front so the iterator doesn't change during the loop
        for snake_key in list(json_obj.keys()):
            value = json_obj.get(snake_key)
            if debug:
                logw(snake_key, "SNAKE KEY")
                logw(value, "VALUE")
            camel_key = snake_to_camel(snake_key, upper=upper, space=space)
            if debug:
                logw(camel_key, "CAMEL KEY")
            value_mro = inspect.getmro(value.__class__)
            if dict in value_mro or list in value_mro:
                if debug:
                    logw(value, "DICT VALUE BEFORE")
                json_snake_to_camel(value, upper=upper, space=space, debug=debug)
                if debug:
                    logw(value, "DICT VALUE AFTER")
            json_obj[camel_key] = value
            if camel_key != snake_key:
                del json_obj[snake_key]
    elif list in mro:
        for item in json_obj:
            if debug:
                logw(item, "LIST ITEM BEFORE")
            json_snake_to_camel(item, upper=upper, space=space, debug=debug)
            if debug:
                logw(item, "LIST ITEM AFTER")


def ts_to_dt(timestamp):
    if timestamp is None: return None
    return datetime.datetime.utcfromtimestamp(timestamp)

def dt_to_ts(dttm, keep_milliseconds=False):
    """ calendar.timegm() doesn't maintain the microseconds awareness of datetime (!?!)
        maintain the milliseconds as an integer to fit into 8 bytes: 1516687988867
        could also for example be sent as decimal representation with microseconds: 1516687988.867397
    """
    if dttm is None: return None
    if keep_milliseconds:
        return int(str(calendar.timegm(dttm.utctimetuple())) + str(dttm.microsecond)[:3])
    else:
        return calendar.timegm(dttm.utctimetuple())


# Make it easier to use ansi escape sequences for terminal colors
colors = {'black' : 30, 'red' : 31, 'green' : 32, 'yellow' : 33, 'blue' : 34,
          'magenta' : 35, 'cyan' : 36, 'white' : 37, 'reset': 39, }
attrs = {'reset':'0', 'bold':'1', 'faint':'2', 'regular':'2',
         'underscore':'4', 'blink':'5', 'reverse':'7'}

def ansi_esc(colorName, **kwargs):
    out = '\x1B['
    if 'attr' in kwargs and kwargs['attr'] in attrs:
        out += attrs[kwargs['attr']] + ';'
    if 'bgcolor' in kwargs and kwargs['bgcolor'] in colors:
        bgcolor = colors[kwargs['bgcolor']] + 10
        out += str(bgcolor) + ';'
    out += str(colors[colorName]) + 'm'
    return out

def cline(line, mode):
    pick_ansi = {'-': 'red', '+': 'green', '*': 'green', '@': 'cyan'}
    color = pick_ansi.get(line[0], '')
    if color != '':
        line = ansi_esc(color) + line + ansi_esc('reset')
    if mode == 'print': print(line)
    if mode == 'return': return line

def cdiff(line):
    pick_ansi = {'-': 'red', '+': 'green', '*': 'green'}
    color = pick_ansi.get(line[0], '')
    if color != '':
        return ansi_esc(color) + line + ansi_esc('reset')
    else:
        return line

def cstr(data, color):
    return ansi_esc(color) + data + ansi_esc('reset')

def nl2br(value):
    return value.replace('\n', '<br />')

def format_integer(number):
    return "{:,}".format(number)

def format_money(amount, rjust=None):
    amt = "%.2f" % amount
    profile = re.compile(r"(\d)(\d\d\d[.,])")
    while 1:
        amt, count = re.subn(profile, r"\1,\2", amt)
        if not count:
            break
    if rjust:
        return amt.rjust(rjust)
    return amt


# >>> "%4.2f Trillion Should Be Enough" % (float(26*pow(36, 7)) / float(pow(1024, 4)))
# '1.85 Trillion Should Be Enough'
# >>> "If Not, %4.2f Trillion Should Definitely Be Enough" % (float(26*pow(36, 9)) / float(pow(1024, 4)))
# 'If Not, 2401.57 Trillion Should Definitely Be Enough'

# Combine with a second factor like a row_id to eliminate unbelievably lucky brute force possibilities. Enforce at least one letter so it can't be cast to an int
token_length = 10
token_chars = string.ascii_letters + string.digits
def magic_token(length=token_length):
    return random.choice(string.ascii_lowercase) + functools.reduce(lambda x, y: x + random.choice(token_chars), range(length-1), '').lower()

def validate_token(row_id, token):
    return validate_int(row_id) and len([ch for ch in token if ch in token_chars]) == token_length

def validate_int(value):
    # int() can't take a None so we have to check that first
    if value is None:
        return None
    # As long as it's a string we can remove commas, since those don't validate
    if type(value) is str:
        value = value.replace(',', '')
    try:
        return int(value)
    except (ValueError, TypeError):
        return None

def validate_date(value):
    if not value:
        return None
    if type(value) is datetime.datetime:
        return value
    try:
        return dateutil.parser.parse(value)
    except (ValueError, TypeError):
        return None

def validate_bool(value):
    if value is None:
        return None
    if type(value) is bool:
        return value
    return bool(value)

def validate_decimal(value):
    if value is None:
        return None
    if type(value) in (float, int):
        return decimal.Decimal(value)
    try:
        value = decimal.Decimal(re.sub(r'[^\d.-]', '', value.strip()))
    except decimal.InvalidOperation:
        return None
    return value

def validate_ip_address(value):
    try:
        ip = ipaddress.ip_address(value)
        return ip
    except:
        return None


email_validator = None
def validate_email(value):
    global email_validator
    if not email_validator:
        email_validator = EmailValidator()
    if value is None:
        return None
    if type(value) is not str:
        return None
    try:
        email_validator.validate(value)
        return value.lower()
    except ValueError:
        logging.warning("Invalid email: %s", value)
        return None

### Adapted from Django: https://github.com/django/django/blob/11b8c30b9e02ef6ecb996ad3280979dfeab700fa/django/core/validators.py
class EmailValidator:
    user_regex = re.compile(
        r"(^[-!#$%&'*+/=?^_`{}|~0-9A-Z]+(\.[-!#$%&'*+/=?^_`{}|~0-9A-Z]+)*\Z"  # dot-atom
        r'|^"([\001-\010\013\014\016-\037!#-\[\]-\177]|\\[\001-\011\013\014\016-\177])*"\Z)',  # quoted-string
        re.IGNORECASE)
    domain_regex = re.compile(
        # max length for domain name labels is 63 characters per RFC 1034
        r'((?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+)(?:[A-Z0-9-]{2,63}(?<!-))\Z',
        re.IGNORECASE)
    literal_regex = re.compile(
        # literal form, ipv4 or ipv6 address (SMTP 4.1.3)
        r'\[([A-f0-9:\.]+)\]\Z',
        re.IGNORECASE)
    domain_whitelist = ['localhost']

    def __init__(self, whitelist=None):
        if whitelist is not None:
            self.domain_whitelist = whitelist

    def validate(self, value):
        if not value or '@' not in value:
            raise ValueError("Email must have @ sign")
        user_part, domain_part = value.rsplit('@', 1)
        if not self.user_regex.match(user_part):
            raise ValueError("Invalid user part")
        if (domain_part not in self.domain_whitelist and not self.validate_domain_part(domain_part)):
            # Try for possible IDN domain-part
            try:
                domain_part = domain_part.encode('idna').decode('ascii')
            except UnicodeError:
                pass
            else:
                if self.validate_domain_part(domain_part):
                    return True
            raise ValueError("Invalid domain part")
        return True

    def validate_domain_part(self, domain_part):
        if self.domain_regex.match(domain_part):
            return True
        literal_match = self.literal_regex.match(domain_part)
        if literal_match:
            ip_address = literal_match.group(1)
            return validate_ip_address(ip_address)
        return False


### Known Robots Handling, used along with user_agents module is_bot()
class RobotValidator:
    robot_patterns = [
        '360Spider',
        '80legs.com/webcrawler',
        'ADmantX',
        '^123peoplebot',
        '^.{1,4}$',
        '^A1 Website Download',
        '^A12$',
        '^A6-Indexer',
        '^abc',
        '^Aboundex',
        '^About.me',
        '^AdnormCrawler',
        '^AdsBot-Google',
        '^Aghaven',
        '^Anemone',
        '^Apache-HttpClient/',
        '^AppEngine-Google;',
        '^Apple-PubSub',
        '^ArcheType',
        '^AsyncHttpClient',
        '^Atomic_Email_Hunter',
        '^Attribot',
        '^BacklinkCrawler',
        '^Baiduspider',
        '^BDFetch',
        '^BigBozz Bot',
        'BingPreview/',
        '^binlar_',
        '^bitlybot',
        '^Browserlet',
        '^BublupBot',
        '^Bufferbot',
        '^CatchBot',
        '^CCBot',
        '^check_http',
        '^checks.panopta.com',
        '^CJNetworkQuality',
        '^CloudACL',
        '^coccoc',
        '^COMODO',
        '^Comodo-Certificates-Spider',
        '^Content Crawler',
        '^ContextAd Bot',
        '^crawl',
        '^Crowsnest',
        '^curl/',
        'Daum/',
        '^Docunator',
        '^DomainCrawler',
        '^Domnutch-Bot',
        '^elefent/Elefent',
        '^EventGuruBot',
        '^EventMachine',
        '^Evolution Crawler',
        '^ExactSeek Crawler',
        '^ExB Language Crawler',
        '^facebookexternalhit',
        '^facebookplatform',
        '^Feedfetcher-Google',
        '^feedfinder',
        '^fetch libfetch',
        '^findlinks',
        '^Firefox 5.0.2$',
        '^Firefox$',
        '^FisigBot',
        '^FlightDeckReportsBot',
        '^GarlikCrawler',
        '^geotest',
        '^Gigabot',
        '^gimme60',
        '^Goldfire Server',
        '^Google-Site-Verification',
        '^Google-Test',
        '^Google_Analytics_Content_Experiments',
        '^Google_Analytics_Snippet_Validator',
        '^Googlebot-Image',
        'Google Favicon',
        '^gsa-crawler',
        '^Hatena::Bookmark',
        '^HuaweiSymantecSpider',
        '^ia_archiver',
        '^ichiro',
        '^InAGist',
        '^InboundScore',
        '^Influencebot',
        '^ip-web-crawler.com',
        '^it2media-domain-crawler',
        '^IXEbot',
        '^Jakarta',
        '^Java',
        '^KD Bot',
        '^Kimengi/nineconnections.com',
        '^larbin',
        '^libwww-perl',
        '^Linguee Bot',
        '^LinkedInBot',
        '^LongURL API',
        '^LSSRocketCrawler',
        '^Luminator',
        '^Maggie',
        '^magpie-crawler',
        '^Mail.RU',
        '^mantam',
        '^Mediapartners-Google',
        '^MetaURI',
        '^Microsoft Windows Network Diagnostics',
        '^MLBot',
        '^montastic-monitor',
        '^Mozilla/.*\(compatible$',
        '^Mozilla/.*Abonti',
        '^Mozilla/.*AcoonBot',
        '^Mozilla/.*AhrefsBot',
        '^Mozilla/.*aiHitBot',
        '^Mozilla/.*AppEngine-Google',
        '^Mozilla/.*archive.org',
        '^Mozilla/.*baidu.com',
        '^Mozilla/.*Baiduspider',
        '^Mozilla/.*BigBozzBot',
        '^Mozilla/.*bingbot',
        '^Mozilla/.*Blekkobot',
        '^Mozilla/.*Butterfly',
        '^Mozilla/.*CareerBot',
        '^Mozilla/.*Cliqusbot',
        '^Mozilla/.*coccoc/',
        '^Mozilla/.*CompSpyBot',
        '^Mozilla/.*Dataprovider Site Explorer',
        '^Mozilla/.*DCPbot',
        '^Mozilla/.*Diffbot',
        '^Mozilla/.*discobot',
        '^Mozilla/.*discoverybot',
        '^Mozilla/.*EasouSpider',
        '^Mozilla/.*Embedly',
        '^Mozilla/.*evc',
        '^Mozilla/.*EventGuruBot',
        '^Mozilla/.*Exositesbot',
        '^Mozilla/.*Ezooms',
        '^Mozilla/.*FacebookStatistics',
        '^Mozilla/.*FlipboardProxy',
        '^Mozilla/.*FriendFeedBot',
        '^Mozilla/.*Genieo',
        '^Mozilla/.*GrapeshotCrawler',
        '^Mozilla/.*Gravitybot',
        '^Mozilla/.*heritrix',
        '^Mozilla/.*HTTrack',
        '^Mozilla/.*ICS\)$'
        '^Mozilla/.*IntelCSbot',
        '^Mozilla/.*ips-agent',
        '^Mozilla/.*JikeSpider',
        '^Mozilla/.*KomodiaBot',
        '^Mozilla/.*lemurwebcrawler',
        '^Mozilla/.*ltbot',
        '^Mozilla/.*LucidWorks',
        '^Mozilla/.*Mail.RU',
        '^Mozilla/.*Memorybot',
        '^Mozilla/.*MJ12bot',
        '^Mozilla/.*MojeekBot',
        '^Mozilla/.*monitis - premium monitoring service',
        '^Mozilla/.*MSIE or Firefox mutant; not on Windows server;',
        '^Mozilla/.*NaverJapan',
        '^Mozilla/.*NerdByNature.Bot',
        '^Mozilla/.*news bot',
        '^Mozilla/.*Nigma.ru',
        '^Mozilla/.*Nmap Scripting Engine',
        '^Mozilla/.*oBot',
        '^Mozilla/.*OpenindexSpider',
        '^Mozilla/.*PaperLiBot',
        '^Mozilla/.*Plukkie',
        '^Mozilla/.*ProCogBot',
        '^Mozilla/.*proximic',
        '^Mozilla/.*redditbot',
        '^Mozilla/.*ReverseGet',
        '^Mozilla/.*Robo',
        '^Mozilla/.*ScoutJet',
        '^Mozilla/.*ScribdReader',
        '^Mozilla/.*search.thunderstone.com',
        '^Mozilla/.*Search17Bot',
        '^Mozilla/.*SearchmetricsBot',
        '^Mozilla/.*SemrushBot',
        '^Mozilla/.*SISTRIX Crawler',
        '^Mozilla/.*SiteBot',
        '^Mozilla/.*SiteExplorer',
        '^Mozilla/.*Sosospider',
        '^Mozilla/.*spbot',
        '^Mozilla/.*special_archiver',
        '^Mozilla/.*Statsbot',
        '^Mozilla/.*Steeler',
        '^Mozilla/.*suggybot',
        '^Mozilla/.*SurveyBot',
        '^Mozilla/.*Swarm',
        '^Mozilla/.*SWEBot',
        '^Mozilla/.*TourlentaScanner',
        '^Mozilla/.*TweetedTimes',
        '^Mozilla/.*TweetmemeBot',
        '^Mozilla/.*Undrip Bot',
        '^Mozilla/.*UnisterBot',
        '^Mozilla/.*WASALive-Bot',
        '^Mozilla/.*Wazzup',
        '^Mozilla/.*WBSearchBot',
        '^Mozilla/.*WebmasterCoffee',
        '^Mozilla/.*woriobot',
        '^Mozilla/.*Yahoo',
        '^Mozilla/.*YandexImages',
        '^Mozilla/.*YioopBot',
        '^Mozilla/.*yolinkBot',
        '^Mozilla/.*YoudaoBot',
        '^Mozilla/.*ZEERCHBOT',
        '^msnbot',
        '^mysmutsearch',
        '^news.me',
        '^newsme',
        '^NextGenSearchBot',
        '^NING',
        'NULL USER AGENT',
        '^Nuzzel',
        '^OpenWebIndex',
        'OutclicksBot',
        '^PagesInventory'
        '^panscient.com',
        '^peerindex',
        '^percbotspider',
        '^PercolateCrawler',
        '^perlclient',
        '^Pingdom',
        '^Pinterest',
        '^PostRank',
        '^psbot',
        '^Python-httplib2',
        '^python-requests',
        '^Python-urllib',
        'Qwantify/'
        '^rbot',
        '^Readability',
        '^Rielee',
        '^RockmeltEmbed',
        '^Ronzoobot',
        '^Ruby',
        '^SaladSpoon',
        '^SAS Web Crawler',
        '^Scope PreviewBot',
        '^Screaming Frog SEO Spider',
        '^Search-Dev',
        '^SemrushBot',
        'Scrapy',
        '^ShortLinkTranslate',
        '^ShowyouBot',
        '^SiteSucker',
        '^SkimBot',
        '^Slurp',
        'SMTBot',
        '^Sogou',
        '^SolomonoBot',
        '^Sosospider',
        '^spider',
        '^spotinfluence',
        '^sqlmap',
        '^squirrobot/',
        '^ssearch_bot',
        '^StatusNet/',
        '^Summify',
        '^Swiftbot',
        '^test',
        '^thumbshots',
        '^TinEye',
        '^TosCrawler',
        '^trovator',
        '^ts_spider',
        '^TurnitinBot',
        '^Twisted',
        '^Twitterbot',
        '^Tweetbot',
        '^UCI IR crawler',
        '^UnwindFetchor',
        '^Updownerbot',
        '^Voyager',
        '^W3C-checklink',
        '^W3C_Validator',
        '^Wada.vn',
        '^Web front page analyser',
        '^Wget',
        '^WinHTTP',
        '^WocBot',
        '^worder',
        '^Wotbox',
        '^wsAnalyzer',
        '^www.integromedb.org',
        '^Xenu Link Sleuth',
        '^Y!J-BRJ/YATS crawler',
        '^yacybot',
        '^Yahoo Pipes',
        '^Yahoo! Slurp China',
        '^Yahoo:LinkExpander',
        '^Yepi/',
        '^Yeti',
        '^yolinkBot',
        'bixo',
        'crawler',
        'Exabot',
        'Google Web Preview',
        'Googlebot',
        'Googlebot-Mobile',
        'ichiro/mobile goo;',
        'InsieveBot',
        'larbin',
        'LinkChecker',
        'MS Search',
        'MSIECrawler',
        'naver.com',
        'Nutch',
        'openwebspider.org',
        'PycURL',
        'Python',
        'ReverseGet',
        'Robot',
        'search.goo.ne.jp',
        'SeznamBot',
        'SISTRIX crawler',
        'SiteIntel.net Bot',
        'Speedy Spider',
        'Spider',
        'StumbleUpon;',
        'TLSProber',
        'trendictionbot',
        'urllib',
        'verticalpigeon.com',
        'VoilaBot',
        'VoilaBotCollector',
        'YamanaLab-Robot',
        'YandexBot',
        'Yeti-Mobile',
        'YodaoBot',
        'Zend_Http_Client',
    ]
    robot_str = "(?i)(?P<robot>" + "|".join(robot_patterns) + ")"
    robot_re = None

# Test Robot with curl -X GET -kH 'User-Agent: Googlebot' https://<hostname>
def is_robot(user_agent):
    if not user_agent:
        return True
    if not RobotValidator.robot_re:
        RobotValidator.robot_re = re.compile(RobotValidator.robot_str)
    return bool(RobotValidator.robot_re.search(user_agent) is not None)


def rate_limit(limit_obj, key, hostname, delta_sec):
    """ Return True if should be rate-limited. Keep attribute on object passed in. """
    attr_name = '%s-%s' % (key, hostname)
    if hasattr(limit_obj, attr_name):
        attr = getattr(limit_obj, attr_name)
        if attr + datetime.timedelta(seconds=delta_sec) > datetime.datetime.now():
            return True
    setattr(limit_obj, attr_name, datetime.datetime.now())
    return False


class TimerObj(object):
    pass

def get_timer(obj=None):
    # Optional object that sets the timer on the object given so it doesn't have to crawl the stack each call
    if obj and hasattr(obj, '_timer_obj'):
        return obj._timer_obj
    frame = inspect.currentframe()
    f_self = frame.f_locals.get('self')
    while not f_self or not hasattr(f_self, 'timer_obj'):
        frame = frame.f_back
        if not frame:
            return None
        f_self = frame.f_locals.get('self')
        if hasattr(f_self, 'timer_obj'):
            if obj:
                obj._timer_obj = f_self.timer_obj
            return f_self.timer_obj

# Timer System for by-hand tracking _timings on any object
def timer_start(obj, timer_name):
    if not obj:
        return {}
    # Initialize _timers on obj
    if not hasattr(obj, '_timers'):
        setattr(obj, '_timers', {})
    # Don't overwrite if it's already been set
    start_name = '_%s_start_ts' % timer_name
    if not obj._timers.get(start_name):
        obj._timers[start_name] =  time.time()

def timer_stop(obj, timer_name):
    if not obj:
        return {}
    start_name = '_%s_start_ts' % timer_name
    stop_name = '_%s_stop_ts' % timer_name
    exec_name = '_%s_exec_s' % timer_name
    # Don't overwrite if it's already been set, and compute execution time
    if not obj._timers.get(stop_name):
        obj._timers[stop_name] = time.time()
        obj._timers[exec_name] = obj._timers[stop_name] - obj._timers[start_name]

def timer_log(obj, timer_name):
    if not obj:
        return {}
    exec_name = '_%s_exec_s' % timer_name
    logging.error("%s  %.3f ms" % (timer_name, 1000 * obj._timers[exec_name]))

def timer_reset(obj, timer_name):
    if not obj:
        return {}
    start_name = '_%s_start_ts' % timer_name
    stop_name = '_%s_stop_ts' % timer_name
    exec_name = '_%s_exec_s' % timer_name
    del obj._timers[start_name]
    del obj._timers[stop_name]
    del obj._timers[exec_name]

def incr_start(obj, timer_name):
    if not obj:
        return {}
    # Initialize _timers on obj
    if not hasattr(obj, '_timers'):
        setattr(obj, '_timers', {})
    # Do overwrite the previous so we can add up the times
    start_name = '_%s_start_ts' % timer_name
    obj._timers[start_name] =  time.time()

def incr_stop(obj, timer_name):
    if not obj:
        return {}
    start_name = '_%s_start_ts' % timer_name
    stop_name = '_%s_stop_ts' % timer_name
    exec_name = '_%s_exec_s' % timer_name
    cnt_name = '_%s_cnt' % timer_name
    # Do overwrite the previous so we can add up the times.
    obj._timers[stop_name] = time.time()
    obj._timers.setdefault(exec_name, 0.0)
    obj._timers.setdefault(cnt_name, 0)
    obj._timers[exec_name] += obj._timers[stop_name] - obj._timers[start_name]
    obj._timers[cnt_name] += 1
