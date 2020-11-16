#!/bin/bash

cd $(dirname "$0")

set -eo pipefail

if test -d pylibrus_env; then
  echo "Directory 'pylibrus_env' already exists!"
  exit 1
fi;

virtualenv -p `which python3` pylibrus_env
source pylibrus_env/bin/activate

set -u

pip install pipenv

pipenv install --skip-lock

script="$(readlink -f pylibrus_env/bin/check_librus.sh)"

if test -e "$script"; then
    echo "File $script already exists"
else
    cat <<EOF > "$script"
#!/bin/bash

source "$(readlink -f pylibrus_env/bin/activate)"

set -xeuo pipefail

export LIBRUS_USER=
export LIBRUS_PASS=

export SMTP_USER=
export SMTP_PASS=
export SMTP_SERVER=

export EMAIL_DEST=

#export DB_NAME=pylibrus.sqlite

#export FETCH_ATTACHMENTS=yes

# define which messages to sent
# - unread - send messages unread in librus
# - unsent - send messages not marked in DB as sent
#export SEND_MESSAGE=unread

#export MAX_AGE_OF_SENDING_MSG_DAYS=4

python3 "$(readlink -f src/pylibrus/pylibrus.py)"

EOF

    chmod +x "$script"
fi;

cat <<EOF

To finish installation make sure all variables in "$script" are set.

To send testing email run:
TEST_EMAIL_CONF=1 "$script"

To run it periodically add entry to your crontab (to edit your crontab run "crontab -e"):

*/10 * * * * "$script"

EOF
