#!/bin/bash
# SPDX-License-Identifier: BSD-2-Clause
# Copyright  (c) 2020-2023, The Chancellor, Masters and Scholars of the University
# of Oxford, and the 'Galv' Developers. All rights reserved.

set -e

# Wrap the user's command to run prematter first
# The prematter relies on envvars, so can't be run at build time

if [ -z "$1" ]; then
    # No custom command provided, so run the default
    COMMAND="gunicorn --bind 0.0.0.0:8000 --workers 2 config.wsgi"
    MESSAGE="Starting server: $COMMAND"
else
    COMMAND="$@"
    MESSAGE="Starting with custom command: $COMMAND"
fi

echo "Setting up database"
(/code/setup_db.sh)
echo "Starting validation monitor process"
(/code/validation_monitor.sh &)
echo "Collecting static files"
python manage.py collectstatic --noinput
echo "$MESSAGE"
exec $COMMAND
