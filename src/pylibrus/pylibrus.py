import base64
import datetime
import logging
import os
import smtplib
import sys
import time
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from http import client as http_client
from itertools import chain

import requests
from bs4 import BeautifulSoup
from sqlalchemy import Column, String, Boolean, DateTime, Integer, LargeBinary, ForeignKey
from sqlalchemy.engine import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from user_agent import generate_user_agent

Base = declarative_base()

MAX_AGE_OF_SENDING_MSG_DAYS = int(os.environ.get("MAX_AGE_OF_SENDING_MSG_DAYS", 4))

FETCH_ATTACHMENTS = os.environ.get("FETCH_ATTACHMENTS", "1").lower() not in ["", "0", "false", "no", "not"]

FAILED_TO_DOWNLOAD_ATTACHMENT_DATA = "Failed to download attachment data!"

SEND_MESSAGE = os.environ.get("SEND_MESSAGE", "unread")

assert SEND_MESSAGE in ("unread", "unsent"), "SEND_MESSAGE should be 'unread' or 'unsent'"


def retrieve_from(txt, start, end):
    pos = txt.find(start)
    if pos == -1:
        return ""
    idx_start = pos + len(start)
    pos = txt.find(end, idx_start)
    if pos == -1:
        return ""
    return txt[idx_start:pos].strip()


class Msg(Base):
    __tablename__ = "messages"

    url = Column(String, primary_key=True)
    folder = Column(Integer)
    sender = Column(String)
    subject = Column(String)
    date = Column(DateTime)
    contents_html = Column(String)
    contents_text = Column(String)
    email_sent = Column(Boolean, default=False)


class Attachment(Base):
    __tablename__ = "attachments"

    link_id = Column(String, primary_key=True)  # link_id seems to contain message id and attachment id
    msg_path = Column(String, ForeignKey(Msg.url))
    name = Column(String)
    data = Column(LargeBinary)


class LibrusScraper(object):
    API_URL = "https://api.librus.pl"
    SYNERGIA_URL = "https://synergia.librus.pl"

    @classmethod
    def synergia_url_from_path(cls, path):
        if path.startswith("https://"):
            return path
        return cls.SYNERGIA_URL + path

    @classmethod
    def api_url_from_path(cls, path):
        return cls.API_URL + path

    @staticmethod
    def msg_folder_path(folder_id):
        return f"/wiadomosci/{folder_id}"

    def __init__(self, login, passwd, debug=False):
        self._login = login
        self._passwd = passwd
        self._session = requests.session()
        self._user_agent = generate_user_agent()
        self._last_folder_msg_path = None
        self._last_url = self.synergia_url_from_path("/")

        if debug:
            http_client.HTTPConnection.debuglevel = 1
            logging.basicConfig()
            logging.getLogger().setLevel(logging.DEBUG)
            requests_log = logging.getLogger("requests.packages.urllib3")
            requests_log.setLevel(logging.DEBUG)
            requests_log.propagate = True

    def _set_headers(self, referer, kwargs):
        if "headers" not in kwargs:
            kwargs["headers"] = {}
        kwargs["headers"].update(
            {
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "pl",
                "User-Agent": self._user_agent,
                "Referer": referer,
            }
        )
        return kwargs

    def _api_post(self, path, referer, **kwargs):
        print(f"post {path}")
        self._set_headers(referer, kwargs)
        return self._session.post(self.api_url_from_path(path), **kwargs)

    def _api_get(self, path, referer, **kwargs):
        print(f"get {path}")
        self._set_headers(referer, kwargs)
        return self._session.get(self.api_url_from_path(path), **kwargs)

    def _request(self, method, path, referer=None, **kwargs):
        if referer is None:
            referer = self._last_url
        print(f"{method} {path} referrer={referer}")
        self._set_headers(referer, kwargs)
        url = self.synergia_url_from_path(path)
        if method == "get":
            resp = self._session.get(url, **kwargs)
        elif method == "post":
            resp = self._session.post(url, **kwargs)
        else:
            raise AssertionError(f"Unsupported method: {method}")
        self._last_url = resp.url
        return resp

    def _post(self, path, referer=None, **kwargs):
        return self._request("post", path, referer, **kwargs)

    def _get(self, path, referer=None, **kwargs):
        return self._request("get", path, referer, **kwargs)

    def __enter__(self):
        oauth_auth_frag = "/OAuth/Authorization?client_id=46"
        oauth_auth_url = self.api_url_from_path(oauth_auth_frag)
        oauth_grant_frag = "/OAuth/Authorization/Grant?client_id=46"
        oauth_captcha_frag = "/OAuth/Captcha"

        self._api_get(
            f"{oauth_auth_frag}&response_type=code&scope=mydata",
            referer="https://portal.librus.pl/rodzina/synergia/loguj",
        )
        self._api_post(
            oauth_captcha_frag,
            referer=oauth_auth_url,
            data={
                "username": self._login,
                "is_needed": 1,
            },
        )
        self._api_post(
            oauth_auth_frag,
            referer=oauth_auth_url,
            data={
                "action": "login",
                "login": self._login,
                "pass": self._passwd,
            },
        )
        self._api_get(oauth_grant_frag, referer=oauth_auth_url)
        return self

    def __exit__(self, exc_type=None, exc_val=None, exc_tb=None):
        pass

    @staticmethod
    def _find_msg_header(soup, name):
        header = soup.find_all(text=name)
        return header[0].parent.parent.parent.find_all("td")[1].text.strip()

    def fetch_attachments(self, msg_path, soup):
        attachments = []
        header = soup.find_all(text="Pliki:")
        if not header:
            return []
        for attachment in header[0].parent.parent.parent.next_siblings:
            _black_dies_without_that_name = """ Example of str(attachment):
            <tr>
            <td>
            <!-- icon -->
            <img src="/assets/img/filetype_icons/doc.png"/>
            <!-- name -->
                                    KOPIOWANIE.docx                    </td>
            <td>
                                     
                                    <!-- download button -->
            <a href="javascript:void(0);">
            <img class="" onclick='

                                    otworz_w_nowym_oknie(
                                        "\/wiadomosci\/pobierz_zalacznik\/4921079\/3664030",
                                        "o2",
                                        420,
                                        250                        )

                                                ' src="/assets/img/homework_files_icons/download.png" title=""/>
            </a>
            </td>
            </tr>
            """
            name = retrieve_from(str(attachment), "<!-- name -->", "</td>")
            if not name:
                continue
            link_id = retrieve_from(str(attachment).replace("\\", ""), "/wiadomosci/pobierz_zalacznik/", '",')
            print(f"Download attachment {name}")
            attachment_page = self._get(f"/wiadomosci/pobierz_zalacznik/{link_id}")

            attach_data = None
            reason = ""
            download_key = retrieve_from(attachment_page.text, 'singleUseKey = "', '"')
            if download_key:

                referer = attachment_page.url
                check_key_url = "https://sandbox.librus.pl/index.php?action=CSCheckKey"
                get_attach_url = f"https://sandbox.librus.pl/index.php?action=CSDownload&singleUseKey={download_key}"
                for _ in range(15):
                    check_ready = self._post(
                        check_key_url,
                        headers={"Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"},
                        referer=referer,
                        data=f"singleUseKey={download_key}",
                    )
                    # print(check_ready.request)
                    # print(check_ready.request.headers)
                    # print(check_ready.request.body)

                    if check_ready.json().get("status") == "ready":
                        get_attach_resp = self._get(get_attach_url)
                        break
                    else:
                        print(f"Waiting for doc: {check_ready.json()}")
                    time.sleep(1)
                else:
                    reason = "waiting for CSCheckKey singleUseKey ready"
            elif "onload=\"window.location.href = window.location.href + '/get';" in attachment_page.text:
                # <body onload="window.location.href = window.location.href + \'/get\';">
                get_attach_resp = self._get(attachment_page.url + "/get")
            else:
                reason = FAILED_TO_DOWNLOAD_ATTACHMENT_DATA

            if get_attach_resp:
                if get_attach_resp.ok:
                    attach_data = get_attach_resp.content
                else:
                    reason = f"http status code: {get_attach_resp.status_code}"

            if reason:
                reason = f"Failed to download attachment: {reason}"
                print(reason)
                attach_data = reason.encode()

            attachments.append(Attachment(link_id=link_id, msg_path=msg_path, name=name, data=attach_data))
            print(f"Attachment name={name}, link={link_id}, size: {len(attach_data)}")

        return attachments

    def fetch_msg(self, msg_path):
        msg_page = self._get(msg_path, referer=self.synergia_url_from_path(self._last_folder_msg_path)).text
        soup = BeautifulSoup(msg_page, "html.parser")
        sender = self._find_msg_header(soup, "Nadawca")
        subject = self._find_msg_header(soup, "Temat")
        date_string = self._find_msg_header(soup, "Wysłano")
        date = datetime.datetime.strptime(date_string, "%Y-%m-%d %H:%M:%S")
        contents = soup.find_all(attrs={"class": "container-message-content"})[0]

        attachments = self.fetch_attachments(msg_path, soup) if FETCH_ATTACHMENTS else []
        return sender, subject, date, str(contents), contents.text, attachments

    def msgs_from_folder(self, folder_id):
        self._last_folder_msg_path = self.msg_folder_path(folder_id)
        ret = self._get(self._last_folder_msg_path, referer=self.synergia_url_from_path("/rodzic/index"))
        inbox_html = ret.text
        soup = BeautifulSoup(inbox_html, "html.parser")
        lines0 = soup.find_all("tr", {"class": "line0"})
        lines1 = soup.find_all("tr", {"class": "line1"})
        msgs = []
        for msg in chain(lines0, lines1):
            all_a_elems = msg.find_all("a")
            if not all_a_elems:
                continue
            link = all_a_elems[0]["href"].strip()
            read = True
            for td in msg.find_all("td"):
                if "bold" in td.get("style", ""):
                    read = False
                    break
            msgs.append((link, read))

        return msgs


def format_sender(sender_info, sender_email):
    sender_b64 = base64.b64encode(sender_info.encode())
    sender_info_encoded = "=?utf-8?B?" + sender_b64.decode() + "?="
    return f'"{sender_info_encoded}" <{sender_email}>'


class LibrusNotifier(object):
    def __init__(self, user, pwd, server, db_name, port=587):
        self._user = user
        self._pwd = pwd
        self._server = server
        self._port = port
        self._engine = None
        self._session = None
        self._db_name = db_name

    def _create_db(self):
        self._engine = create_engine("sqlite:///" + self._db_name)
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

    def get_msg(self, url):
        return self._session.query(Msg).get(url)

    def add_msg(self, url, folder_id, sender, date, subject, contents_html, contents_text, attachments):
        msg = self._session.query(Msg).get(url)
        if not msg:
            msg = Msg(
                url=url,
                folder=folder_id,
                sender=sender,
                date=date,
                subject=subject,
                contents_html=contents_html,
                contents_text=contents_text,
            )
            self._session.add(msg)
            for attachment in attachments:
                self._session.add(attachment)
        return msg

    def send_email(self, recipients, msg_from_db):

        sender = msg_from_db.sender
        subject = msg_from_db.subject
        body_html = msg_from_db.contents_html
        body_text = msg_from_db.contents_text

        if not isinstance(recipients, (list, tuple, set)):
            recipients = [recipients]

        msg = MIMEMultipart("alternative")
        msg.set_charset("utf-8")

        msg["Subject"] = subject
        msg["From"] = format_sender(sender, self._user)
        msg["To"] = ", ".join(recipients)

        html_part = MIMEText(body_html, "html")
        text_part = MIMEText(body_text, "plain")
        msg.attach(html_part)
        msg.attach(text_part)

        if self._session:  # sending testing email doesn't have opened session
            attachments = self._session.query(Attachment).filter(Attachment.msg_path == msg_from_db.url).all()
            for attach in attachments:
                part = MIMEApplication(attach.data, Name=attach.name)
                part["Content-Disposition"] = 'attachment; filename="%s"' % attach.name
                msg.attach(part)

        if self._server and self._pwd:
            server = smtplib.SMTP(self._server, self._port)
            server.ehlo()
            server.starttls()
            server.login(self._user, self._pwd)
            server.sendmail(self._user, recipients, msg.as_string())
            server.close()
        else:
            print(f"Would have send {msg.as_string()}")


def main():
    inbox_folder_id = 5  # Odebrane

    db_name = os.environ.get("DB_NAME") or "pylibrus.sqlite"

    librus_debug = os.environ.get("LIBRUS_DEBUG", False)
    email_user = os.environ.get("SMTP_USER", "Default user")
    email_password = os.environ.get("SMTP_PASS")
    email_server = os.environ.get("SMTP_SERVER")

    email_dest = [email.strip() for email in os.environ["EMAIL_DEST"].split(",")]

    if os.environ.get("TEST_EMAIL_CONF"):
        notifier = LibrusNotifier(email_user, email_password, email_server, db_name=db_name)
        print("Sending testing email")
        notifier.send_email(
            email_dest,
            Msg(
                url="/fake/object",
                folder="Odebrane",
                sender="Testing sender Żółta Jaźń [Nauczyciel]",
                date=datetime.datetime.now(),
                subject="Testing subject with żółta jaźć",
                contents_html="<h2>html content with żółta jażń</h2>",
                contents_text="text content with żółta jaźń",
            ),
        )
        return 2

    librus_user = os.environ.get("LIBRUS_USER")
    librus_password = os.environ.get("LIBRUS_PASS")
    if not librus_user or not librus_password:
        sys.stderr.write("LIBRUS_USER and LIBRUS_PASS must be set")
        return 3

    with LibrusScraper(librus_user, librus_password, debug=librus_debug) as scraper:
        with LibrusNotifier(email_user, email_password, email_server, db_name=db_name) as notifier:
            msgs = scraper.msgs_from_folder(inbox_folder_id)
            for msg_path, read in msgs:

                msg = notifier.get_msg(msg_path)

                if not msg:
                    print(f"Fetch {msg_path}")
                    sender, subject, date, contents_html, contents_text, attachments = scraper.fetch_msg(msg_path)
                    msg = notifier.add_msg(
                        msg_path, inbox_folder_id, sender, date, subject, contents_html, contents_text, attachments
                    )

                if SEND_MESSAGE == "unsent" and msg.email_sent:
                    print(f"Do not send '{msg.subject}' (message already sent)")
                elif SEND_MESSAGE == "unread" and read:
                    print(f"Do not send '{msg.subject}' (message already read)")
                elif datetime.datetime.now() - msg.date > datetime.timedelta(days=MAX_AGE_OF_SENDING_MSG_DAYS):
                    print(f"Do not send '{msg.subject}' (message too old, {msg.date})")
                else:
                    print(f"Sending '{msg.subject}' to {email_dest} from {msg.sender}")
                    notifier.send_email(email_dest, msg)
                    msg.email_sent = True


if __name__ == "__main__":
    sys.exit(main())
