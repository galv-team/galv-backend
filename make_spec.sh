#!/usr/bin/env bash
API_VERSION=$(python manage.py diffsettings | grep API_VERSION | grep -oEi '[0-9]+\.[0-9]+\.[0-9]+')
python manage.py spectacular --format openapi-json >> /spec/openapi-$API_VERSION.json
