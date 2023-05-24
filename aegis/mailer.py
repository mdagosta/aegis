# E-mail utilities
#
# A lot is adapted from https://mg.pov.lt/blog/unicode-emails-in-python


# Python Imports
import datetime
import email.charset
import email.header
import email.mime.multipart
import email.mime.text
import email.utils
import json
import logging
import smtplib

# Extern Imports
from tornado.options import options
import aegis.model
import aegis.stdlib
import pytz
import tornado.template

# Project Imports
import config


# Use Quoted-printable encoding instead of base64 since it's far more legible at a glance! From https://bugs.python.org/issue12552
email.charset.add_charset('utf-8', email.charset.SHORTEST, email.charset.QP)

class Mailer(object):
    template_registry = {}


    @classmethod
    def register_template(cls, domain, email_type_name, function):
        cls.template_registry.setdefault(domain, {})
        cls.template_registry[domain][email_type_name] = function


    @classmethod
    def mime(cls, txt, subtype):
        if txt is None:
            return None
        return email.mime.text.MIMEText(txt, subtype, 'UTF-8')


    @classmethod
    def encode_email(cls, sender, recipient, subject, body, reply_to, service_sender):
        plain, html = None, None
        if isinstance(body, str):
            plain = body
        else:
            plain = body.get('plain', None)
            html = body.get('html', None)
        header_charset = 'utf-8'
        parts = []
        if plain:
            parts.append(cls.mime(plain, 'plain'))
        if html:
            parts.append(cls.mime(html, 'html'))
        if len(parts) > 1:
            msg = email.mime.multipart.MIMEMultipart('alternative')
            for p in parts:
                msg.attach(p)
        else:
            msg = parts[0]
        # Set up headers
        headers = (('To', recipient), ('From', sender), ('Reply-to', reply_to),
                   ('Sender', service_sender))
        for header in headers:
            if not header[1]:
                continue
            name, addr = email.utils.parseaddr(header[1])
            name = str(email.header.Header(name, header_charset))
            if header[0] == 'To' and name:
                msg[header[0]] = '"%s" <%s>' % (name.replace('"', "'"), addr)
            else:
                msg[header[0]] = email.utils.formataddr((name, addr))
        # Finish message
        msg['Subject'] = email.header.Header(subject, header_charset)
        return msg.as_string()


    @classmethod
    def render_email(cls, handler, from_email, to_addrs, subject, template, email_opts, **kwargs):
        if not handler:
            host_config = config.hostnames[kwargs['domain']]
            template_loader = tornado.template.Loader(host_config['template_path'])
            plain = ''
            html = ''
            try:
                plain = template_loader.load(template+'.txt').generate(**email_opts)
            except FileNotFoundError as ex:
                if kwargs.get('debug'):
                    logging.exception("Couldn't render plaintext email for template: %s" % template)
            try:
                html = template_loader.load(template+'.html').generate(**email_opts)
            except FileNotFoundError as ex:
                if kwargs.get('debug'):
                    logging.exception("Couldn't render HTML email for template: %s" % template)
        else:
            plain = handler.render_string('%s.txt' % template, **email_opts)
            html =  handler.render_string('%s.html' % template, **email_opts)
        body = {'plain': plain, 'html': html}
        reply_to = kwargs.get('reply_to', from_email)
        service_sender = kwargs.get('service_sender', from_email)
        return cls.encode_email(from_email, to_addrs, subject, body, reply_to, service_sender)


    @classmethod
    def send_mailer(cls, email_tracking_id, dbconn):
        #aegis.stdlib.logw("in mail.send_mailer")
        email_tracking = aegis.model.EmailTracking.get_id(email_tracking_id, dbconn=dbconn)
        email_type = aegis.model.EmailType.get_id(email_tracking['email_type_id'], dbconn=dbconn)
        email_data = json.loads(email_tracking['email_data'])
        # Check to/from emails and format accordingly
        from_email = aegis.model.Email.get_id(email_tracking['from_email_id'], dbconn=dbconn)
        email_data['from_addr'] = from_email['email']
        to_email = aegis.model.Email.get_id(email_tracking['to_email_id'], dbconn=dbconn)
        if to_email['delete_dttm']:
            logging.error("Not sending to deleted email_id: %s", to_email['to_email_id'])
            email_tracking.mark_deleted(dbconn=dbconn)
            return False
        email_data['to_addr'] = to_email['email']
        # Turn this into a (first_name or email) if it's a member
        if to_email['member_id']:
            to_member = aegis.model.Member.get_auth(to_email['member_id'], dbconn=dbconn)
            if to_member:
                email_data['to_email'] = to_email['email']
                if to_member.get('google_user', {}).get('name'):
                    email_data['to_name'] = to_member['google_user']['name']
                else:
                    email_data['to_name'] = ''
        kwargs = {}
        kwargs['domain'] = email_data['domain'] = dbconn.domain
        # Call an email template function if it has already been registered.
        if kwargs['domain'] in cls.template_registry and cls.template_registry[kwargs['domain']]:
            domain_templates = cls.template_registry[kwargs['domain']]
            fn = domain_templates[email_type['email_type_name']]
            email_data = fn(email_data)
        kwargs['reply_to'] = email_data['from_addr']
        email_data['nl2br'] = aegis.stdlib.nl2br
        email_data['format_integer'] = aegis.stdlib.format_integer
        # It's a mouthful to convert this to Pacific time
        # XXX TODO this should be on UTC, maybe without timezone information
        email_data['send_dttm_str'] = email_tracking['send_dttm'].astimezone(pytz.timezone('US/Pacific')).strftime('%b %d, %Y, %-H:%-M %p')
        email_data['options'] = options
        email_data['current_year'] = datetime.date.today().year
        email_data['email_tracking_id'] = email_tracking_id
        email_data['email_uuid'] = email_tracking['email_uuid']
        email_template = 'email/%s' % email_type['template_name']
        #kwargs['debug'] = True
        email_msg = cls.render_email(None, email_data['from_addr'], email_data['to_addr'], email_data['subject'], email_template, email_data, **kwargs)
        if email_msg:
            #logging.warning(email_msg)
            sent = cls.sendmail(from_email['email'], to_email['email'], email_msg)
            # Record email_tracking as sent
            if sent:
                email_tracking.mark_sent(dbconn=dbconn)
            return True
        return False


    @classmethod
    def sendmail(cls, from_addr, to_addrs, msg):
        if not options.smtp_host or not options.smtp_port:
            return logging.warning('No SMTP host or port supplied, not sending email')
        try:
            if options.smtp_user:
                conn = smtplib.SMTP_SSL(options.smtp_host, options.smtp_port)
                conn.login(options.smtp_user, options.smtp_pass)
            else:
                conn = smtplib.SMTP(options.smtp_host, options.smtp_port)
            conn.sendmail(from_addr, to_addrs, msg)
            logging.warning('Sent email to: %s' % to_addrs)
            return conn.quit()
        except Exception as ex:
            logging.exception(ex)
