#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright  (c) 2020-2023, The Chancellor, Masters and Scholars of the University
# of Oxford, and the 'Galv' Developers. All rights reserved.

set -e

>&2 echo "DJANGO_TEST=${DJANGO_TEST}"
>&2 echo "DJANGO_SETTINGS=${DJANGO_SETTINGS}"
python manage.py makemigrations
python manage.py migrate
python manage.py create_superuser
>&2 echo "... populating database"
python manage.py loaddata galv/fixtures/*
