#!/bin/bash
# SPDX-License-Identifier: BSD-2-Clause
# Copyright  (c) 2020-2023, The Chancellor, Masters and Scholars of the University
# of Oxford, and the 'Galv' Developers. All rights reserved.

set -m  # enable job control

echo "Setting up database"
(/code/setup_db.sh)
echo "Starting validation monitor process"
(/code/validation_monitor.sh &)
echo "Collecting static files"
python manage.py collectstatic --noinput
echo "Starting server"
gunicorn --bind unix:///tmp/gunicorn.sock --workers 2 config.wsgi &
sleep 10 && nginx && service nginx start  # wait for gunicorn to start before starting nginx
fg %-
