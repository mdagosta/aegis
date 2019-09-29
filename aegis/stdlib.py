#-*- coding: utf-8 -*-


# Python Imports
import decimal
import hashlib
import ipaddress
import inspect
import logging
import os
import pprint
import random
import re
import string
import xml


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

def logline(*args):
    caller = get_caller()
    msg = '%s %s' % (cstr(caller, 'yellow').ljust(20), args[0])
    logging.warning(msg, *args[1:])

def force_int(string):
    if type(string) in (int, int): return int(string)
    int_re = re.compile('^.*?(\d+).*?$')
    match = int_re.match(string)
    if not match: return None
    return int(match.group(1))

def md5hex(val):
    return hashlib.md5(val).hexdigest()

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


def magic_key(length=8):
    return reduce(lambda x, y: x + random.choice(string.ascii_letters + string.digits), range(length), '').lower()


def validate_int(value):
    # int() can't take a None so we have to check that first
    if value is None:
        return None
    # As long as it's a string we can remove commas, since those don't validate
    if type(value) is str:
        value = value.replace(',', '')
    try:
        return int(value)
    except ValueError:
        return None

def validate_date(value):
    if not value:
        return None
    if type(value) is datetime.datetime:
        return value
    try:
        return dateutil.parser.parse(value)
    except ValueError:
        return None

def validate_bool(value):
    if valid is None:
        return None
    if type(value) is bool:
        return value
    return bool(value)

def validate_decimal(value):
    if value is None:
        return None
    try:
        value = decimal.Decimal(re.sub(r'[^\d.]', '', value))
    except decimal.InvalidOperation:
        return None
    return value

def validate_email(value):
    try:
        logging.error("IT IS TIME. Port the Django from below")
        cleaned_email = django.forms.EmailField(required=True).clean(value)
        return cleaned_email
    except django.forms.ValidationError:
        logging.warning("Invalid email: %s", value)
        return None

def validate_ip_address(value):
    try:
        ip = ipaddress.ip_address(value)
        return ip
    except:
        return None



### From Django: https://github.com/django/django/blob/11b8c30b9e02ef6ecb996ad3280979dfeab700fa/django/core/validators.py

#@deconstructible
#class EmailValidator:
#    message = _('Enter a valid email address.')
#    code = 'invalid'
#    user_regex = _lazy_re_compile(
#        r"(^[-!#$%&'*+/=?^_`{}|~0-9A-Z]+(\.[-!#$%&'*+/=?^_`{}|~0-9A-Z]+)*\Z"  # dot-atom
#        r'|^"([\001-\010\013\014\016-\037!#-\[\]-\177]|\\[\001-\011\013\014\016-\177])*"\Z)',  # quoted-string
#        re.IGNORECASE)
#    domain_regex = _lazy_re_compile(
#        # max length for domain name labels is 63 characters per RFC 1034
#        r'((?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+)(?:[A-Z0-9-]{2,63}(?<!-))\Z',
#        re.IGNORECASE)
#    literal_regex = _lazy_re_compile(
#        # literal form, ipv4 or ipv6 address (SMTP 4.1.3)
#        r'\[([A-f0-9:\.]+)\]\Z',
#        re.IGNORECASE)
#    domain_whitelist = ['localhost']
#
#    def __init__(self, message=None, code=None, whitelist=None):
#        if message is not None:
#            self.message = message
#        if code is not None:
#            self.code = code
#        if whitelist is not None:
#            self.domain_whitelist = whitelist
#
#    def __call__(self, value):
#        if not value or '@' not in value:
#            raise ValidationError(self.message, code=self.code)
#
#        user_part, domain_part = value.rsplit('@', 1)
#
#        if not self.user_regex.match(user_part):
#            raise ValidationError(self.message, code=self.code)
#
#        if (domain_part not in self.domain_whitelist and
#                not self.validate_domain_part(domain_part)):
#            # Try for possible IDN domain-part
#            try:
#                domain_part = domain_part.encode('idna').decode('ascii')
#            except UnicodeError:
#                pass
#            else:
#                if self.validate_domain_part(domain_part):
#                    return
#            raise ValidationError(self.message, code=self.code)
#
#    def validate_domain_part(self, domain_part):
#        if self.domain_regex.match(domain_part):
#            return True
#
#        literal_match = self.literal_regex.match(domain_part)
#        if literal_match:
#            ip_address = literal_match.group(1)
#            try:
#                validate_ipv46_address(ip_address)
#                return True
#            except ValidationError:
#                pass
#        return False
#
#    def __eq__(self, other):
#        return (
#            isinstance(other, EmailValidator) and
#            (self.domain_whitelist == other.domain_whitelist) and
#            (self.message == other.message) and
#            (self.code == other.code)
#        )
