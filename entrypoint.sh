#!/bin/sh

set -e
set -x

envsubst < /etc/config/Rolodex.toml.in > Rolodex.toml

exec "$@"
