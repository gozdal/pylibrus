# pyLibrus

Message scraper from crappy Librus Synergia gradebook. Forwards every new
message from a given folder to an e-mail.

## Running

* Make sure you have [installed `uv`](https://github.com/astral-sh/uv?tab=readme-ov-file#installation)
* Checkout **pylibrus** repository
* Verify everything's installed correctly with `uv run src/pylibrus/pylibrus.py --help`
* Setup `pylibrus.ini` according to [`pylibrus.ini.example`](pylibrus.ini.example)
* Run from cron every few minutes

## Potential improvements

* support HTML messages
* support announcements
* support calendar
