# E-mail utilities
#
# A lot is adapted from https://mg.pov.lt/blog/unicode-emails-in-python


# Python Imports
import logging
import email.mime.text
import email.mime.multipart
import email.utils
import email.header
import json
import smtplib

# Extern Imports
import pytz
import tornado.template
from tornado.options import options
import aegis.model
import aegis.stdlib

# Project Imports
import config


def mime(txt, subtype):
    if txt is None:
        return None
    return email.mime.text.MIMEText(txt, subtype, 'UTF-8')


def encode_email(sender, recipient, subject, body, reply_to, service_sender):
    plain, html = None, None
    if isinstance(body, str):
        plain = body
    else:
        plain = body.get('plain', None)
        html = body.get('html', None)
    header_charset = 'utf-8'
    parts = []
    if plain:
        parts.append(mime(plain, 'plain'))
    if html:
        parts.append(mime(html, 'html'))
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


def render_email(handler, from_email, to_addrs, subject, template, email_opts, **kwargs):
    if not handler:
        host_config = config.hostnames[kwargs['domain']]
        template_loader = tornado.template.Loader(host_config['template_path'])
        plain = ''
        html = ''
        try:
            plain = template_loader.load(template+'.txt').generate(**email_opts)
        except:
            logging.exception("Couldn't render plaintext email for template: %s" % template)
            pass
        try:
            html = template_loader.load(template+'.html').generate(**email_opts)
        except:
            logging.exception("Couldn't render HTML email for template: %s" % template)
            pass
    else:
        plain = handler.render_string('%s.txt' % template, **email_opts)
        html =  handler.render_string('%s.html' % template, **email_opts)
    body = {'plain': plain, 'html': html}
    reply_to = kwargs.get('reply_to', from_email)
    service_sender = kwargs.get('service_sender', from_email)
    return encode_email(from_email, to_addrs, subject, body, reply_to, service_sender)


def send_mailer(email_tracking_id, dbconn):
    #aegis.stdlib.logw("in mail.send_mailer")
    email_tracking = aegis.model.EmailTracking.get_id(email_tracking_id, dbconn=dbconn)
    email_type = aegis.model.EmailType.get_id(email_tracking['email_type_id'], dbconn=dbconn)
    email_data = json.loads(email_tracking['email_data'])
    # Check to/from emails and format accordingly
    from_email = aegis.model.Email.get_id(email_tracking['from_email_id'], dbconn=dbconn)
    from_addr = from_email['email']
    to_email = aegis.model.Email.get_id(email_tracking['to_email_id'], dbconn=dbconn)
    to_addr = to_email['email']
    # Turn this into a (first_name or email) if it's a member
    if to_email['member_id']:
        to_member = aegis.model.Member.get_auth(to_email['member_id'], dbconn=dbconn)
        if to_member:
            email_data['to_email'] = to_email['email']
            if to_member.get('given_name') and to_member.get('family_name'):
                email_data['to_name'] = '%s %s' % (to_member['given_name'], to_member['family_name'])
            else:
                email_data['to_name'] = ''
    kwargs = {}
    kwargs['domain'] = dbconn.domain
    # Email types need to call out to the parent, somehow. So it needs to be connected in.
    if email_type['email_type_name'] == 'Welcome':
        subject = 'Welcome!'
        from_addr = kwargs['reply_to'] = email.utils.formataddr( (email_data['from_name'], from_email['email']) )
        to_addr = email.utils.formataddr( (email_data['to_name'], to_email['email']) )
    email_data['nl2br'] = aegis.stdlib.nl2br
    email_data['format_integer'] = aegis.stdlib.format_integer
    # It's a mouthful to convert this to Pacific time
    email_data['send_dttm_str'] = email_tracking['send_dttm'].astimezone(pytz.timezone('US/Pacific')).strftime('%b %d, %Y, %-H:%-M %p')
    email_data['options'] = options
    email_template = 'email/%s' % email_type['template_name']
    email_msg = render_email(None, from_addr, to_addr, subject, email_template, email_data, **kwargs)
    if email_msg:
        logging.warning("Could send email!")
        logging.warning(email_msg)
        sent = sendmail(from_email['email'], to_email['email'], email_msg)
        # Record email_tracking as sent
        if sent:
            email_tracking.mark_sent(dbconn=dbconn)
        return True
    return False


def sendmail(from_addr, to_addrs, msg):
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
