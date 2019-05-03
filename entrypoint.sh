#!/bin/sh

set -e
set -x

envsubst < /etc/Rolodex.toml.in > Rolodex.toml

exec rolodex "$@"
