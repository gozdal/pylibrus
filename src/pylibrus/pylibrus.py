import abc
import base64
import configparser
import dataclasses
import datetime
import json
import logging
import os
import smtplib
import sys
import time
from configparser import ConfigParser
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from http import client as http_client
from itertools import chain
from textwrap import dedent

import requests
from bs4 import BeautifulSoup
from sqlalchemy import Column, String, Boolean, DateTime, Integer, LargeBinary, ForeignKey
from sqlalchemy.engine import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
from user_agent import generate_user_agent

Base = declarative_base()

FAILED_TO_DOWNLOAD_ATTACHMENT_DATA = "Failed to download attachment data!"
CONFIG_FILE_PATH = os.path.realpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "pylibrus.ini"))
TRUE_VALUES = ('yes', 'on', 'true', '1')
FALSE_VALUES = ('no', 'off', 'false', '0')


def str_to_bool(s: str):
    if s is None:
        return None
    s = s.lower()
    if s in TRUE_VALUES:
        return True
    elif s in FALSE_VALUES:
        return False
    else:
        raise ValueError(f"Invalid boolean value: {s}. Should be one of: {list(TRUE_VALUES) + list(FALSE_VALUES)} ")


def str_to_int(s: str):
    if s is None:
        return None
    return int(s)

@dataclasses.dataclass(slots=True)
class PyLibrusConfig:
    send_message: str = "unread"
    fetch_attachments: bool = True
    max_age_of_sending_msg_days: int = 4
    db_name: str = "pylibrus.sqlite"
    debug: bool = False
    loop_and_sleep_seconds: int = 0
    inbox_folder_id: int = dataclasses.field(default=5, init=False)  # Odebrane


    def __post_init__(self):
        for field in dataclasses.fields(self):
            if not isinstance(field.default, dataclasses._MISSING_TYPE) and getattr(self, field.name) is None:
                setattr(self, field.name, field.default)
        if self.send_message not in ("unread", "unsent"):
            raise ValueError("SEND_MESSAGE should be 'unread' or 'unsent'")

    @classmethod
    def from_config(cls, config: ConfigParser) -> "PyLibrusConfig":
        return cls(
            send_message=config["global"].get(PyLibrusConfig.send_message.__name__, None),
            fetch_attachments=config["global"].getboolean(PyLibrusConfig.fetch_attachments.__name__, None),
            max_age_of_sending_msg_days=config["global"].getint(PyLibrusConfig.max_age_of_sending_msg_days.__name__, None),
            db_name=config["global"].get(PyLibrusConfig.db_name.__name__, None),
            debug=config["global"].getboolean(PyLibrusConfig.debug.__name__, None),
            loop_and_sleep_seconds=config["global"].getint(PyLibrusConfig.loop_and_sleep_seconds.__name__, None),
        )

    @classmethod
    def from_env(cls) -> "PyLibrusConfig":
        return cls(
            send_message=os.environ.get("SEND_MESSAGE"),
            fetch_attachments=str_to_bool(os.environ.get("FETCH_ATTACHMENTS")),
            max_age_of_sending_msg_days=str_to_int(os.environ.get("MAX_AGE_OF_SENDING_MSG_DAYS")),
            db_name=os.environ.get("DB_NAME"),
            debug=str_to_bool(os.environ.get("LIBRUS_DEBUG")),
        )

PYLIBRUS_CONFIG: PyLibrusConfig | None = None

def validate_fields(instance):
    for field in dataclasses.fields(instance):
        value = getattr(instance, field.name)
        if value is None or value == "":
            raise ValueError(f"The field '{field.name}' cannot be None.")


class Notify(abc.ABC):
    @staticmethod
    def is_email() -> bool:
        return False

    @staticmethod
    def is_webhook() -> bool:
        return False


@dataclasses.dataclass(slots=True)
class EmailNotify(Notify):
    smtp_user: str
    smtp_pass: str = dataclasses.field(repr=False)
    smtp_server: str
    email_dest: list[str] | str
    smtp_port: int = 587

    @staticmethod
    def is_email() -> bool:
        return True

    def __post_init__(self):
        if isinstance(self.email_dest, str):
            self.email_dest = [email.strip() for email in self.email_dest.split(",")]
        for field in dataclasses.fields(self):
            if not isinstance(field.default, dataclasses._MISSING_TYPE) and getattr(self, field.name) is None:
                setattr(self, field.name, field.default)
        validate_fields(self)

    @classmethod
    def from_env(cls) -> "EmailNotify":
        return cls(
            smtp_user=os.environ.get("SMTP_USER", "Default user"),
            smtp_pass=os.environ.get("SMTP_PASS"),
            smtp_server=os.environ.get("SMTP_SERVER"),
            smtp_port=int(os.environ.get("SMTP_PORT")),
            email_dest=os.environ.get("EMAIL_DEST"),
        )

    @classmethod
    def from_config(cls, config, section) -> "EmailNotify":
        return cls(
            smtp_user=config[section]['smtp_user'],
            smtp_pass=config[section]['smtp_pass'],
            smtp_server=config[section]['smtp_server'],
            smtp_port=int(config[section]['smtp_port']),
            email_dest=config[section]['email_dest']
        )



@dataclasses.dataclass(slots=True)
class WebhookNotify(Notify):
    webhook: str

    @staticmethod
    def is_webhook() -> bool:
        return True

    def __post_init__(self):
        validate_fields(self)

    @classmethod
    def from_env(cls) -> "WebhookNotify":
        return cls(webhook=os.environ.get("WEBHOOK"))

    @classmethod
    def from_config(cls, config, section):
        return cls(
            webhook=config[section]['webhook']
        )



@dataclasses.dataclass(slots=True)
class LibrusUser:
    login: str
    password: str = dataclasses.field(repr=False)
    name: str
    notify: EmailNotify | WebhookNotify

    @classmethod
    def from_config(cls, config, section) -> "LibrusUser":
        name = section.split(':', 1)[1]
        librus_user = config[section].get('librus_user')
        librus_pass = config[section].get('librus_pass')
        # Determine whether the user uses email or webhook notification
        if 'email_dest' in config[section]:
            notify = EmailNotify.from_config(config, section)
        elif 'webhook' in config[section]:
            notify = WebhookNotify.from_config(config, section)
        else:
            raise ValueError(f"No valid notification method for {section}")
        return cls(name=name, login=librus_user, password=librus_pass, notify=notify)

    @classmethod
    def from_env(cls) -> "LibrusUser":
        return cls(
            login=os.environ.get("LIBRUS_USER"),
            password=os.environ.get("LIBRUS_PASS"),
            name=os.environ.get("LIBRUS_NAME"),
            notify=WebhookNotify.from_env() if str_to_bool(os.environ.get("WEBHOOK")) else EmailNotify.from_env()
        )

    @classmethod
    def load_librus_users_from_config(cls, config: ConfigParser) -> list["LibrusUser"]:
        users = []
        for section in config.sections():
            if section.startswith("user:"):
                user = cls.from_config(config, section)
                users.append(user)
        return users


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


def retrieve_from(txt, start, end):
    pos = txt.find(start)
    if pos == -1:
        return ""
    idx_start = pos + len(start)
    pos = txt.find(end, idx_start)
    if pos == -1:
        return ""
    return txt[idx_start:pos].strip()

class LibrusScraper(object):
    API_URL = "https://api.librus.pl"
    SYNERGIA_URL = "https://synergia.librus.pl"

    @classmethod
    def get_attachment_download_link(cls, link_id: str):
        return f"{cls.SYNERGIA_URL}/wiadomosci/pobierz_zalacznik/{link_id}"

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
        debug(f"post {path}")
        self._set_headers(referer, kwargs)
        return self._session.post(self.api_url_from_path(path), **kwargs)

    def _api_get(self, path, referer, **kwargs):
        debug(f"get {path}")
        self._set_headers(referer, kwargs)
        return self._session.get(self.api_url_from_path(path), **kwargs)

    def _request(self, method, path, referer=None, **kwargs):
        if referer is None:
            referer = self._last_url
        debug(f"{method} {path} referrer={referer}")
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
        oauth_2fa_frag = "/OAuth/Authorization/2FA?client_id=46"

        self._api_get(
            f"{oauth_auth_frag}&response_type=code&scope=mydata",
            referer="https://portal.librus.pl/rodzina/synergia/loguj",
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
        self._api_get(oauth_2fa_frag, referer=oauth_auth_url)
        return self

    def __exit__(self, exc_type=None, exc_val=None, exc_tb=None):
        pass
    "#body > div.container.static > div > table > tbody > tr:nth-child(1) > td"

    @staticmethod
    def _find_msg_header(soup, name):
        header = soup.find_all(string=name)
        return header[0].parent.parent.parent.find_all("td")[1].text.strip()

    def fetch_attachments(self, msg_path, soup, fetch_content):

        header = soup.find_all(string="Pliki:")
        if not header:
            return []

        def get_attachments_without_data() -> list[Attachment]:
            attachments = []
            for attachment in header[0].parent.parent.parent.next_siblings:
                _black_dies_without_that_name = r""" Example of str(attachment):
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
                attachments.append(Attachment(link_id=link_id, msg_path=msg_path, name=name, data=None))

            return attachments

        attachments = get_attachments_without_data()

        if not fetch_content:
            return attachments

        for attachment in attachments:
            print(f"Download attachment {attachment.name}")
            download_link = LibrusScraper.get_attachment_download_link(str(attachment.link_id))
            attachment_page = self._get(download_link)

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

                    if check_ready.json().get("status") == "ready":
                        get_attach_resp = self._get(get_attach_url)
                        break
                    else:
                        print(f"Waiting for doc: {check_ready.json()}")
                    time.sleep(1)
                else:
                    reason = "waiting for CSCheckKey singleUseKey ready"
            elif "onload=\"window.location.href = window.location.href + '/get';" in attachment_page.text:
                get_attach_resp = self._get(attachment_page.url + "/get")
            else:
                reason = FAILED_TO_DOWNLOAD_ATTACHMENT_DATA

            if get_attach_resp is not None:
                if get_attach_resp.ok:
                    attach_data = get_attach_resp.content
                else:
                    reason = f"http status code: {get_attach_resp.status_code}"

            if reason:
                reason = f"Failed to download attachment: {reason}"
                print(reason)
                attach_data = reason.encode()

            attachment.data=attach_data
            print(f"Attachment name={attachment.name}, link={attachment.link_id}, size: {len(attach_data)}")

        return attachments

    def fetch_msg(self, msg_path, fetch_attchement_content: bool):
        global PYLIBRUS_CONFIG
        msg_page = self._get(msg_path, referer=self.synergia_url_from_path(self._last_folder_msg_path)).text
        soup = BeautifulSoup(msg_page, "html.parser")
        sender = self._find_msg_header(soup, "Nadawca")
        subject = self._find_msg_header(soup, "Temat")
        date_string = self._find_msg_header(soup, "Wysłano")
        date = datetime.datetime.strptime(date_string, "%Y-%m-%d %H:%M:%S")
        if datetime.datetime.now() - date > datetime.timedelta(days=PYLIBRUS_CONFIG.max_age_of_sending_msg_days):
            print(f"Do not send '{subject}' (message too old, {date})")
            return None
        contents = soup.find_all(attrs={"class": "container-message-content"})[0]

        attachments = self.fetch_attachments(msg_path, soup, fetch_attchement_content)
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
        msgs.reverse()
        return msgs


class LibrusNotifier(object):
    def __init__(self, librus_user: LibrusUser, db_name):
        self._librus_user = librus_user
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
        return self._session.get(Msg, url)

    def add_msg(self, url, folder_id, sender, date, subject, contents_html, contents_text, attachments):
        msg = self.get_msg(url)
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

    def notify(self, msg_from_db):
        if self._librus_user.notify.is_webhook():
            print(f"Sending '{msg_from_db.subject}' to webhook from {msg_from_db.sender} ({msg_from_db.date})")
            self.send_via_webhook(msg_from_db)
        else:
            print(f"Sending '{msg_from_db.subject}' to {self._librus_user.notify.email_dest} from {msg_from_db.sender}")
            self.send_email(msg_from_db)

    def send_via_webhook(self, msg_from_db):
        attachments_name = []
        if self._session:
            attachments = self._session.query(Attachment).filter(Attachment.msg_path == msg_from_db.url).all()
            attachemnt_to_download_link = {attach.name: LibrusScraper.get_attachment_download_link(attach.link_id) for attach in attachments}
            for attach in attachments:
                attachments_name.append(attach.name)

        msg = dedent(f"""
        *LIBRUS {self._librus_user.name} - {msg_from_db.date}*
        *Od: {msg_from_db.sender}*
        *Temat: {msg_from_db.subject}*
        """) + f"\n{msg_from_db.contents_text}"
        if attachemnt_to_download_link:
            msg += f"\n\nZałączniki:\n"
            for attachment_name, link in attachemnt_to_download_link.items():
                msg += f"- <{link}|{attachment_name}>\n"
        message = {
            'text': msg,
        }

        response = requests.post(
            self._librus_user.notify.webhook, data=json.dumps(message),
            headers={'Content-Type': 'application/json'}
        )

        if response.status_code != 200:
            print(f'Failed to send message. Status code: {response.status_code}')

    @staticmethod
    def format_sender(sender_info, sender_email):
        sender_b64 = base64.b64encode(sender_info.encode())
        sender_info_encoded = "=?utf-8?B?" + sender_b64.decode() + "?="
        return f'"{sender_info_encoded}" <{sender_email}>'

    def send_email(self, msg_from_db):
        msg = MIMEMultipart("alternative")
        msg.set_charset("utf-8")

        msg["Subject"] = msg_from_db.subject
        msg["From"] = self.format_sender(msg_from_db.sender, self._librus_user.notify.smtp_user)
        msg["To"] = ", ".join(self._librus_user.notify.email_dest)

        attachments_only_with_link: list[Attachment] = []
        attachments_with_data: list[Attachment] = []
        if self._session:  # sending testing email doesn't have opened session
            attachments = self._session.query(Attachment).filter(Attachment.msg_path == msg_from_db.url).all()
            for attach in attachments:
                if attach.data is None:
                    attachments_only_with_link.append(attach)
                else:
                    attachments_with_data.append(attach)
        attachments_as_text_msg = "" if not attachments_only_with_link else "\n\nZałączniki:\n" + "\n - ".join(LibrusScraper.get_attachment_download_link(att.link_id) for att in attachments_only_with_link)
        attachments_as_html_msg = "" if not attachments_only_with_link else "<br/><br/><p>Załączniki:<p><ul>" + "".join(f"<li><a href='{LibrusScraper.get_attachment_download_link(att.link_id)}'>{att.name}</a></li>" for att in attachments_only_with_link) + "</ul>"

        html_part = MIMEText(msg_from_db.contents_html + attachments_as_html_msg, "html")
        text_part = MIMEText(msg_from_db.contents_text + attachments_as_text_msg, "plain")
        msg.attach(html_part)
        msg.attach(text_part)
        for attach in attachments_with_data:
            part = MIMEApplication(attach.data, Name=attach.name)
            part["Content-Disposition"] = 'attachment; filename="%s"' % attach.name
            msg.attach(part)

        server = smtplib.SMTP(self._librus_user.notify.smtp_server, self._librus_user.notify.smtp_port)
        server.ehlo()
        server.starttls()
        server.login(self._librus_user.notify.smtp_user, self._librus_user.notify.smtp_pass)
        server.sendmail(self._librus_user.notify.smtp_user, self._librus_user.notify.email_dest, msg.as_string())
        server.close()

def read_pylibrus_config() -> tuple[PyLibrusConfig, list[LibrusUser]]:
    if os.path.exists(CONFIG_FILE_PATH):
        print(f"Read config from file: {CONFIG_FILE_PATH}")
        config = configparser.ConfigParser()
        config.read(CONFIG_FILE_PATH)
        pylibrus_config = PyLibrusConfig.from_config(config)
        librus_users = LibrusUser.load_librus_users_from_config(config)
        return pylibrus_config, librus_users
    else:
        print(f"Could not find config file: {CONFIG_FILE_PATH}, read config from env variables")
        pylibrus_config = PyLibrusConfig.from_env()
        librus_users = [LibrusUser.from_env()]
    return pylibrus_config, librus_users

def debug(msg):
    global PYLIBRUS_CONFIG
    if PYLIBRUS_CONFIG.debug:
        print(msg)


def main():
    global PYLIBRUS_CONFIG
    pylibrus_config, librus_users = read_pylibrus_config()
    PYLIBRUS_CONFIG = pylibrus_config
    print(f"Config: {PYLIBRUS_CONFIG}")
    for user in librus_users:
        print(f"User: {user}")

    test_notify = str_to_bool(os.environ.get("TEST_EMAIL_CONF")) or str_to_bool(os.environ.get("TEST_NOTIFY"))

    if test_notify:
        notifier = LibrusNotifier(librus_users[0], db_name=PYLIBRUS_CONFIG.db_name)
        msg = Msg(
                url="/fake/object",
                folder="Odebrane",
                sender="Testing sender Żółta Jaźń [Nauczyciel]",
                date=datetime.datetime.now(),
                subject="Testing subject with żółta jaźć",
                contents_html="<h2>html content with żółta jażń</h2>",
                contents_text="text content with żółta jaźń",
            )
        print("Sending testing notify")
        notifier.notify(msg)
        return 2

    while True:
        for librus_user in librus_users:
            with LibrusScraper(librus_user.login, librus_user.password, debug=PYLIBRUS_CONFIG.debug) as scraper:
                with LibrusNotifier(librus_user, db_name=PYLIBRUS_CONFIG.db_name) as notifier:
                    msgs = scraper.msgs_from_folder(PYLIBRUS_CONFIG.inbox_folder_id)
                    for msg_path, read in msgs:

                        msg = notifier.get_msg(msg_path)

                        if not msg:
                            debug(f"Fetch {msg_path}")

                            fetch_attachment_content = PYLIBRUS_CONFIG.fetch_attachments and librus_user.notify.is_email()
                            msg_content_or_none = scraper.fetch_msg(msg_path, fetch_attachment_content)
                            if msg_content_or_none is None:
                                continue
                            sender, subject, date, contents_html, contents_text, attachments = msg_content_or_none
                            msg = notifier.add_msg(
                                msg_path, PYLIBRUS_CONFIG.inbox_folder_id, sender, date, subject, contents_html, contents_text, attachments
                            )

                        if PYLIBRUS_CONFIG.send_message == "unsent" and msg.email_sent:
                            print(f"Do not send '{msg.subject}' (message already sent)")
                        elif PYLIBRUS_CONFIG.send_message == "unread" and read:
                            print(f"Do not send '{msg.subject}' (message already read)")
                        else:
                            notifier.notify(msg)
                            msg.email_sent = True
            if len(librus_users) > 1:
                time.sleep(60)
        if pylibrus_config.loop_and_sleep_seconds <= 0:
            break
        time.sleep(pylibrus_config.loop_and_sleep_seconds)


    # TEST MISSING LIBRUS USER  AND LIBRUS_PARAM!
    # pylibrus.ini.example
    # install.sh bash script
    # maybe? sent attachments to slack
    # README.md - fix
if __name__ == "__main__":
    sys.exit(main())
