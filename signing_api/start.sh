#!/bin/sh
set -eu
mkdir -p "${SIGNING_DATA_DIR:-/data/docuseal/signing}"
chown 2000:2000 "${SIGNING_DATA_DIR:-/data/docuseal/signing}"
chmod 700 "${SIGNING_DATA_DIR:-/data/docuseal/signing}"
cd /app
exec su docuseal -s /bin/sh -c '/app/bin/bundle exec puma -b tcp://0.0.0.0:3000 -t 1:2 signing_api/config.ru'
