#!/bin/bash
# SPDX-License-Identifier: BSD-2-Clause
# Copyright  (c) 2020-2023, The Chancellor, Masters and Scholars of the University
# of Oxford, and the 'Galv' Developers. All rights reserved.

set -e

W=${WORKERS:-4}
TO=${TIMEOUT:-60}

# Wrap the user's command to run prematter first
# The prematter relies on envvars, so can't be run at build time

if [ -z "$1" ]; then
    # No custom command provided, so run the default
    # Determine the number of workers from number of cores * 4
    COMMAND="gunicorn --bind localhost:8000 --workers $W --timeout $TO config.wsgi"
    MESSAGE="Starting server: $COMMAND"
else
    COMMAND="$@"
    MESSAGE="Starting with custom command: $COMMAND"
fi

echo "Starting nginx proxy"
service nginx start
echo ""
echo "Setting up database"
(/code/setup_db.sh)
echo "Starting validation monitor process"
(/code/validation_monitor.sh &)
echo "Collecting static files"
python manage.py collectstatic --noinput
echo "$MESSAGE"
exec $COMMAND
