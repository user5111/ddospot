import collections
import datetime
import hashlib
import logging
import os
import shutil
import smtplib
import socket
import threading
import time
import urllib.request

import geoip2.database

from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText


class Alerter(object):
    def __init__(self, conf, name):
        self.name = name
        self.logger = logging.getLogger(name)
        mail_host = self._conf_or_env(conf, 'mail_host', 'DDOSPOT_MAIL_HOST')
        mail_port = int(self._conf_or_env(conf, 'mail_port', 'DDOSPOT_MAIL_PORT'))
        mail_username = self._conf_or_env(conf, 'mail_username', 'DDOSPOT_MAIL_USERNAME')
        mail_password = self._conf_or_env(conf, 'mail_password', 'DDOSPOT_MAIL_PASSWORD')
        mail_sec = self._conf_or_env(conf, 'mail_sec', 'DDOSPOT_MAIL_SEC')
        if mail_sec == 'None':
            mail_sec = None
        self.mail_from = self._conf_or_env(conf, 'mail_from', 'DDOSPOT_MAIL_FROM')
        mail_to = self._conf_or_env(conf, 'mail_to', 'DDOSPOT_MAIL_TO')
        self.mail_to_list = [e.strip() for e in mail_to.split(',')]
        self.mail_subject = conf.get('alerting', 'mail_subject')
        self.honeypot_name = conf.get('alerting', 'honeypot_name', fallback=name)
        self.trigger_country_list = [e.strip() for e in conf.get('alerting', 'trigger_countries').split(',')]
        self.notification_rate = conf.getint('alerting', 'notification_rate')
        self.notification_allowance = float(self.notification_rate)
        self.last_notification_sent = time.time()

        # queue has space for 10 messages
        self.notification_queue = collections.deque(maxlen=10)

        # default flush interval for notification thread (default to 5 seconds)
        self.flush_interval = 5

        try:
            self.mailer = Mailer(
                                 mail_host,
                                 mail_port,
                                 mail_username,
                                 mail_password,
                                 mail_sec,
                                 conf.getint('alerting', 'mail_timeout', fallback=30)
                                 )
        except MailerError as msg:
            self.logger.error('Error creating alerter: %s' % (msg))

        try:
            db_path = os.environ.get('DDOSPOT_GEOIP_DB') or 'db/GeoIP-Country.mmdb'
            self._ensure_geoip_db(db_path, 'Country-without-asn.mmdb')
            self.geoip_reader = geoip2.database.Reader(db_path)
        except Exception as msg:
            self.logger.error('Error initializing GeoIP country reader: %s' % (msg))
            self.geoip_reader = None

        try:
            asn_path = os.environ.get('DDOSPOT_GEOIP_ASN_DB') or 'db/GeoIP-ASN.mmdb'
            self._ensure_geoip_db(asn_path, 'GeoLite2-ASN.mmdb')
            self.geoip_asn_reader = geoip2.database.Reader(asn_path)
        except Exception as msg:
            self.logger.error('Error initializing GeoIP ASN reader: %s' % (msg))
            self.geoip_asn_reader = None

        t = threading.Thread(target=self._flush_notifications)
        t.daemon = True
        t.start()

    @staticmethod
    def _conf_or_env(conf, option, env_var):
        value = os.environ.get(env_var)
        if value:
            return value
        return conf.get('alerting', option)

    def _ensure_geoip_db(self, db_path, src):
        if os.path.exists(db_path) and os.path.getsize(db_path) > 0:
            return
        base = 'https://cdn.jsdelivr.net/gh/Loyalsoldier/geoip@release'
        os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
        tmp = db_path + '.tmp'
        self.logger.info('GeoIP mmdb not found at %s, downloading from %s/%s' % (db_path, base, src))
        urllib.request.urlretrieve('%s/%s' % (base, src), tmp)
        expected = urllib.request.urlopen('%s/%s.sha256sum' % (base, src)).read().decode().split()[0]
        actual = hashlib.sha256(open(tmp, 'rb').read()).hexdigest()
        if actual != expected:
            os.remove(tmp)
            raise Exception('GeoIP mmdb sha256 mismatch: expected %s, got %s' % (expected, actual))
        shutil.move(tmp, db_path)
        self.logger.info('GeoIP mmdb downloaded and verified (%d bytes)' % os.path.getsize(db_path))

    def alert(self, ip, port, msg=None):
        # alerting functionality is rather slow because of geoip lookup and name resolution
        # notify user asynchronously in additional thread and do not wait for thread finish
        t = threading.Thread(target=self._do_alert, args=(ip, port, msg))
        t.daemon = True
        t.start()

    def _do_alert(self, ip, port, msg=None):
        if not self.geoip_reader:
            return

        try:
            response = self.geoip_reader.country(ip)
            ip_country = response.country.iso_code
            ip_country_name = response.country.name
        except Exception:
            return

        if ip_country in self.trigger_country_list:
            host = self._get_host(ip)

            asn_info = 'N/A'
            if self.geoip_asn_reader:
                try:
                    asn_resp = self.geoip_asn_reader.asn(ip)
                    asn_info = 'AS%d %s' % (asn_resp.autonomous_system_number, asn_resp.autonomous_system_organization)
                except Exception:
                    asn_info = 'N/A'

            if msg is None:
                msg = '[%s] %s detected attack on %s (%s) port %d | Country: %s (%s) | ASN: %s | %s' % (
                    self.honeypot_name, self.name, ip, host, port,
                    ip_country, ip_country_name, asn_info,
                    datetime.datetime.now())
            self.notification_queue.append(msg)

    # rate limiting based on https://stackoverflow.com/questions/667508/whats-a-good-rate-limiting-algorithm#
    def _flush_notifications(self):
        while True:
            # if notification queue is not empty, flush messages with appropriate rate-limiting
            while self.notification_queue:
                now = time.time()
                time_since_last_notif = now - self.last_notification_sent
                self.notification_allowance += time_since_last_notif * (self.notification_rate / 60.0)
                if (self.notification_allowance > self.notification_rate):
                    self.notification_allowance = float(self.notification_rate)
                if (self.notification_allowance < 1.0):
                    # rate limit effect!
                    time.sleep(self.flush_interval)
                else:
                    msg = self.notification_queue.popleft()
                    self.logger.info('Sending mail notification: %s' % (msg))
                    try:
                        self.mailer.send(
                                         self.mail_from,
                                         self.mail_to_list,
                                         email_subject=self.mail_subject,
                                         email_text=msg
                                         )
                        self.last_notification_sent = time.time()
                    except Exception as msg:
                        self.logger.error('Error sending mail notification: %s' % (msg))
                self.notification_allowance -= 1.0

            # if queue is empty, just wait until msg is received
            time.sleep(self.flush_interval)

    def _get_host(self, ip):
        try:
            data = socket.gethostbyaddr(ip)
            host = repr(data[0])
            return host
        except Exception:
            # fail gracefully
            return 'UNKNOWN'


class MailerError(Exception):
    pass


class Mailer(object):
    def __init__(self, host='localhost', port=0, username=None, password=None, smtp_sec=None, timeout=30, pem_priv_key=None, pem_cert_chain=None):
        self.host = host

        # SMTP security is either None (plain-text: port 25), SSL (465) or STARTTLS (port 587)
        if smtp_sec is not None:
            smtp_sec = smtp_sec.upper()
            if smtp_sec != 'SSL' and smtp_sec != 'STARTTLS':
                raise MailerError('Unknown smtp_sec: %s - Use None, SSL or STARTTLS' % (smtp_sec))
        self.smtp_sec = smtp_sec

        if port is None:
            if smtp_sec is None:
                port = 25
            elif smtp_sec == 'SSL':
                port = 465
            elif smtp_sec == 'STARTTLS':
                port = 587

        self.port = port

        if username is None or password is None:
            raise MailerError('SMTP username and password cannot be empty!')

        self.username = username
        self.password = password
        self.timeout = timeout
        self.pem_priv_key = pem_priv_key
        self.pem_cert_chain = pem_cert_chain

    def send(self, email_from=None, email_to=[], email_cc=[], email_bcc=[], email_subject=None, email_text=None, email_raw=None, email_html=None, email_attachments=[]):
        socket_default_timeout = socket.getdefaulttimeout()
        socket.setdefaulttimeout(self.timeout)
        try:
            if email_from is None:
                raise MailerError('Mail sender must be specified!')
            if not email_to:
                raise MailerError('Mail recepient must be specified!')
            if email_raw is None and email_subject is None:
                raise MailerError('Mail subject must be specified!')

            if self.smtp_sec is None or self.smtp_sec == 'STARTTLS':
                smtp = smtplib.SMTP(host=self.host, port=self.port, timeout=self.timeout)
            elif self.smtp_sec == 'SSL':
                smtp = smtplib.SMTP_SSL(host=self.host, port=self.port, timeout=self.timeout, keyfile=self.pem_priv_key, certfile=self.pem_cert_chain)

            smtp.ehlo_or_helo_if_needed()

            if self.smtp_sec == 'STARTTLS':
                smtp.starttls(keyfile=self.pem_priv_key, certfile=self.pem_cert_chain)
                smtp.ehlo()

            smtp.login(self.username, self.password)
            to_str = ','.join([e.strip() for e in email_to])
            cc_str = ','.join([e.strip() for e in email_cc])
            bcc_str = ','.join([e.strip() for e in email_bcc])

            if email_raw is None:
                msg = MIMEMultipart('mixed')
                msg['Subject'] = email_subject
                msg['From'] = email_from
                msg['To'] = to_str
                msg['CC'] = cc_str

                part = MIMEMultipart('alternative')

                if email_text is not None:
                    part.attach(MIMEText(email_text.encode('utf-8'), 'plain', 'utf-8'))
                if email_html is not None:
                    part.attach(MIMEText(email_html.encode('utf-8'), 'html', 'utf-8'))
                msg.attach(part)

                for attachment in email_attachments:
                    with open(attachment, 'rb') as f:
                        attachment_data = f.read()
                        part = MIMEApplication(attachment_data)
                        part.add_header('Content-Disposition', 'attachment', filename=os.path.basename(attachment))
                        msg.attach(part)

                email_raw = msg.as_string()

            smtp.sendmail(email_from, to_str + cc_str + bcc_str, email_raw)

            try:
                smtp.quit()
            except smtplib.SMTPServerDisconnected:
                # sometimes this exception happens on smtp.quit(), ignorable (probably) - the email's already been sent
                pass
        finally:
            socket.setdefaulttimeout(socket_default_timeout)
