from __future__ import print_function

import datetime
import logging
import os
import requests
import smtplib
import sys
from bs4 import BeautifulSoup
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from fake_useragent.fake import UserAgent
from http import client as http_client
from itertools import chain
from sqlalchemy import Column, String, Boolean, DateTime, Integer
from sqlalchemy.engine import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

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
    LIBRUS_URL = 'https://synergia.librus.pl'

    @classmethod
    def librus_url(cls, path):
        return cls.LIBRUS_URL + path

    def __init__(self, login, passwd, debug=False):
        self._login = login
        self._passwd = passwd
        self._session = requests.session()
        self._ua = UserAgent()

        if debug:
            http_client.HTTPConnection.debuglevel = 1
            logging.basicConfig()
            logging.getLogger().setLevel(logging.DEBUG)
            requests_log = logging.getLogger("requests.packages.urllib3")
            requests_log.setLevel(logging.DEBUG)
            requests_log.propagate = True

    def _fix_headers(self, kwargs):
        if 'headers' not in kwargs:
            kwargs['headers'] = {}
        kwargs['headers'] = {
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'pl',
            'User-Agent': self._ua.random,
            'Referer': self.librus_url('/loguj'),
        }
        return kwargs

    def _post(self, url, **kwargs):
        self._fix_headers(kwargs)
        return self._session.post(self.librus_url(url), **kwargs)

    def _get(self, url, **kwargs):
        self._fix_headers(kwargs)
        return self._session.get(self.librus_url(url), **kwargs)

    def __enter__(self):
        ret = self._get('/loguj')
        ret = self._post('/loguj', data={
            'login': self._login,
            'passwd': self._passwd,
            'ed_pass_keydown': "",
            'ed_pass_keyup': "",
            'captcha': "",
            'czy_js': '1',
        })
        return self

    def __exit__(self, exc_type=None, exc_val=None, exc_tb=None):
        pass

    def _find_msg_header(self, soup, name):
        header = soup.find_all(text=name)
        return header[0].parent.parent.parent.find_all('td')[1].text.strip()

    def fetch_msg(self, link):
        msg_page = self._get(link).text
        soup = BeautifulSoup(msg_page, 'html.parser')
        sender = self._find_msg_header(soup, 'Nadawca')
        subject = self._find_msg_header(soup, 'Temat')
        date_string = self._find_msg_header(soup, 'Wysłano')
        date = datetime.datetime.strptime(date_string, '%Y-%m-%d %H:%M:%S')
        contents = soup.find_all(attrs={'class': 'container-message-content'})[0]
        return sender, subject, date, str(contents), contents.text

    def inbox(self, folder_id=5):
        ret = self._get('/wiadomosci/{folder_id}'.format(folder_id=folder_id))
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

        server = smtplib.SMTP(self._server, self._port)
        server.ehlo()
        server.starttls()
        server.login(self._user, self._pwd)
        server.sendmail(self._user, recipients, msg.as_string())
        server.close()


def main():
    folder_id = 5  # Odebrane

    db_name = os.environ['DB_NAME']

    librus_user = os.environ['LIBRUS_USER']
    librus_password = os.environ['LIBRUS_PASS']

    email_user = os.environ['SMTP_USER']
    email_password = os.environ['SMTP_PASS']
    email_server = os.environ['SMTP_SERVER']

    email_dest = [email.strip() for email in os.environ['EMAIL_DEST'].split(',')]

    with LibrusScraper(librus_user, librus_password, debug=False) as scraper:
        msgs = scraper.inbox(folder_id=folder_id)
        with LibrusNotifier(email_user, email_password, email_server, db_name=db_name) as notifier:
            for url, read in msgs:
                sender, subject, date, contents_html, contents_text = scraper.fetch_msg(url)
                msg = notifier.add_msg(url, folder_id, sender, date, subject, contents_html, contents_text)
                if not read and not msg.email_sent:
                    print('Sending \'{subject}\' to {email}'.format(subject=subject, email=email_dest))
                    notifier.send_email(email_dest, sender, subject, contents_html, contents_text)
                    msg.email_sent = True


if __name__ == '__main__':
    sys.exit(main())
