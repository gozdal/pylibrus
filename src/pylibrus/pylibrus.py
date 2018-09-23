import datetime
import logging
import os
import smtplib
import sys
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from http import client as http_client
from itertools import chain

import requests
from bs4 import BeautifulSoup
from sqlalchemy import Column, String, Boolean, DateTime, Integer
from sqlalchemy.engine import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from user_agent import generate_user_agent

Base = declarative_base()


class Msg(Base):
    __tablename__ = 'messages'

    url = Column(String, primary_key=True)
    folder = Column(Integer)
    sender = Column(String)
    subject = Column(String)
    date = Column(DateTime)
    contents_html = Column(String)
    contents_text = Column(String)
    email_sent = Column(Boolean, default=False)


class LibrusScraper(object):
    API_URL = 'https://api.librus.pl'
    SYNERGIA_URL = 'https://synergia.librus.pl'

    @classmethod
    def synergia_url_from_path(cls, path):
        return cls.SYNERGIA_URL + path

    @classmethod
    def api_url_from_path(cls, path):
        return cls.API_URL + path

    @staticmethod
    def msg_folder_path(folder_id):
        return '/wiadomosci/{folder_id}'.format(folder_id=folder_id)

    def __init__(self, login, passwd, debug=False):
        self._login = login
        self._passwd = passwd
        self._session = requests.session()
        self._user_agent = generate_user_agent()
        self._last_folder_msg_path = None

        if debug:
            http_client.HTTPConnection.debuglevel = 1
            logging.basicConfig()
            logging.getLogger().setLevel(logging.DEBUG)
            requests_log = logging.getLogger("requests.packages.urllib3")
            requests_log.setLevel(logging.DEBUG)
            requests_log.propagate = True

    def _set_headers(self, referer, kwargs):
        if 'headers' not in kwargs:
            kwargs['headers'] = {}
        kwargs['headers'] = {
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'pl',
            'User-Agent': self._user_agent,
            'Referer': referer,
        }
        return kwargs

    def _api_post(self, path, referer, **kwargs):
        self._set_headers(referer, kwargs)
        return self._session.post(self.api_url_from_path(path), **kwargs)

    def _api_get(self, path, referer, **kwargs):
        self._set_headers(referer, kwargs)
        return self._session.get(self.api_url_from_path(path), **kwargs)

    def _post(self, path, referer, **kwargs):
        self._set_headers(referer, kwargs)
        return self._session.post(self.synergia_url_from_path(path), **kwargs)

    def _get(self, path, referer, **kwargs):
        self._set_headers(referer, kwargs)
        return self._session.get(self.synergia_url_from_path(path), **kwargs)

    def __enter__(self):
        oauth_auth_frag = '/OAuth/Authorization?client_id=46'
        oauth_auth_url = self.api_url_from_path(oauth_auth_frag)
        oauth_grant_frag = '/OAuth/Authorization/Grant?client_id=46'
        oauth_captcha_frag = '/OAuth/Captcha'

        self._api_get('{oauth_fragment}&response_type=code&scope=mydata'.format(oauth_fragment=oauth_auth_frag),
                      referer='https://portal.librus.pl/rodzina/synergia/loguj')
        self._api_post(oauth_captcha_frag,
                       referer=oauth_auth_url,
                       data={
                           'username': self._login,
                           'is_needed': 1,
                       })
        self._api_post(oauth_auth_frag,
                       referer=oauth_auth_url,
                       data={
                           'action': 'login',
                           'login': self._login,
                           'pass': self._passwd,
                       })
        self._api_get(oauth_grant_frag, referer=oauth_auth_url)
        return self

    def __exit__(self, exc_type=None, exc_val=None, exc_tb=None):
        pass

    def _find_msg_header(self, soup, name):
        header = soup.find_all(text=name)
        return header[0].parent.parent.parent.find_all('td')[1].text.strip()

    def fetch_msg(self, msg_path):
        msg_page = self._get(msg_path,
                             referer=self.synergia_url_from_path(self._last_folder_msg_path)).text
        soup = BeautifulSoup(msg_page, 'html.parser')
        sender = self._find_msg_header(soup, 'Nadawca')
        subject = self._find_msg_header(soup, 'Temat')
        date_string = self._find_msg_header(soup, 'Wysłano')
        date = datetime.datetime.strptime(date_string, '%Y-%m-%d %H:%M:%S')
        contents = soup.find_all(attrs={'class': 'container-message-content'})[0]
        return sender, subject, date, str(contents), contents.text

    def msgs_from_folder(self, folder_id):
        self._last_folder_msg_path = self.msg_folder_path(folder_id)
        ret = self._get(self._last_folder_msg_path,
                        referer=self.synergia_url_from_path('/rodzic/index'))
        inbox_html = ret.text
        soup = BeautifulSoup(inbox_html, 'html.parser')
        lines0 = soup.find_all('tr', {'class': 'line0'})
        lines1 = soup.find_all('tr', {'class': 'line1'})
        msgs = []
        for msg in chain(lines0, lines1):
            link = msg.find_all('a')[0]['href'].strip()
            read = True
            for td in msg.find_all('td'):
                if 'bold' in td.get('style', ''):
                    read = False
                    break

            msgs.append((link, read))
        return msgs


class LibrusNotifier(object):
    def __init__(self, user, pwd, server, db_name='pylibrus.sqlite', port=587):
        self._user = user
        self._pwd = pwd
        self._server = server
        self._port = port
        self._engine = None
        self._session = None
        self._db_name = db_name

    def _create_db(self):
        self._engine = create_engine('sqlite:///' + self._db_name)
        Base.metadata.create_all(self._engine)
        session_maker = sessionmaker(bind=self._engine)
        self._session = session_maker()

    def __enter__(self):
        self._create_db()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type is None:
            if self._session:
                self._session.commit()
        else:
            self._session.rollback()

    def add_msg(self, url, folder_id, sender, date, subject, contents_html, contents_text):
        msg = self._session.query(Msg).get(url)
        if not msg:
            msg = Msg(url=url, folder=folder_id, sender=sender, date=date, subject=subject,
                      contents_html=contents_html, contents_text=contents_text)
            self._session.add(msg)
        return msg

    def send_email(self, recipients, sender, subject, body_html, body_text):
        if not isinstance(recipients, (list, tuple, set)):
            recipients = [recipients]

        msg = MIMEMultipart("alternative")
        msg.set_charset("utf-8")

        msg["Subject"] = subject
        msg["From"] = '"{sender}" <{email}>'.format(sender=sender, email=self._user)
        msg["To"] = ', '.join(recipients)

        html_part = MIMEText(body_html, 'html')
        text_part = MIMEText(body_text, 'plain')
        msg.attach(html_part)
        msg.attach(text_part)

        if self._server and self._pwd:
            server = smtplib.SMTP(self._server, self._port)
            server.ehlo()
            server.starttls()
            server.login(self._user, self._pwd)
            server.sendmail(self._user, recipients, msg.as_string())
            server.close()
        else:
            print('Would have send {msg}'.format(msg=msg.as_string()))


def main():
    inbox_folder_id = 5  # Odebrane

    db_name = os.environ['DB_NAME']

    librus_user = os.environ['LIBRUS_USER']
    librus_password = os.environ['LIBRUS_PASS']
    librus_debug = os.environ.get('LIBRUS_DEBUG', False)

    email_user = os.environ.get('SMTP_USER', 'Default user')
    email_password = os.environ.get('SMTP_PASS')
    email_server = os.environ.get('SMTP_SERVER')

    email_dest = [email.strip() for email in os.environ['EMAIL_DEST'].split(',')]

    with LibrusScraper(librus_user, librus_password, debug=librus_debug) as scraper:
        with LibrusNotifier(email_user, email_password, email_server, db_name=db_name) as notifier:
            msgs = scraper.msgs_from_folder(inbox_folder_id)
            for msg_path, read in msgs:
                sender, subject, date, contents_html, contents_text = scraper.fetch_msg(msg_path)
                msg = notifier.add_msg(msg_path, inbox_folder_id, sender, date, subject, contents_html, contents_text)
                if not read and not msg.email_sent:
                    print('Sending \'{subject}\' to {email}'.format(subject=subject, email=email_dest))
                    notifier.send_email(email_dest, sender, subject, contents_html, contents_text)
                    msg.email_sent = True


if __name__ == '__main__':
    sys.exit(main())
