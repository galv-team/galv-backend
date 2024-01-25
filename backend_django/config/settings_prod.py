# SPDX-License-Identifier: BSD-2-Clause
# Copyright  (c) 2020-2023, The Chancellor, Masters and Scholars of the University
# of Oxford, and the 'Galv' Developers. All rights reserved.

"""
Django settings for backend_django project.

Generated by 'django-admin startproject' using Django 4.1.3.

For more information on this path, see
https://docs.djangoproject.com/en/4.1/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/4.1/ref/settings/
"""
import os
import dj_database_url

key = os.environ.get('DJANGO_SECRET_KEY')
if not key:
    raise Exception("Missing environment variable DJANGO_SECRET_KEY")
SECRET_KEY = os.environ.get('DJANGO_SECRET_KEY')

from .settings_base import *

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = os.environ.get('DJANGO_DEBUG', 'False') == 'True'

CSRF_TRUSTED_ORIGINS = [
    *CORS_ALLOWED_ORIGINS,
    f'https://{os.environ.get("VIRTUAL_HOST")}'
]

CSRF_COOKIE_SECURE = True
SESSION_COOKIE_SECURE = True

SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')

# Database
# https://docs.djangoproject.com/en/4.1/ref/settings/#databases

# First port of call is the DATABASE_URL environment variable
# This means we can support fly.io's postgresql service

if os.environ.get('DATABASE_URL'):
    print("Setting DATABASES from DATABASE_URL")
    DATABASES = {
        'default': dj_database_url.config()
    }
else:

    db_host = os.environ.get('POSTGRES_HOST')
    db_port = os.environ.get('POSTGRES_PORT')
    db_user = os.environ.get('POSTGRES_USER')
    db_password = os.environ.get('POSTGRES_PASSWORD')

    if not db_host or not db_port or not db_user or not db_password:
        vars = {
            "POSTGRES_HOST": db_host,
            "POSTGRES_PORT": db_port,
            "POSTGRES_USER": db_user,
            "POSTGRES_PASSWORD": db_password
        }
        raise Exception(f"Missing environment variables: {', '.join([k for k, v in vars.items() if not v])}")

    DATABASES = {
        'default': {
            'ENGINE': 'django.db.backends.postgresql_psycopg2',
            'NAME': 'postgres',
            'HOST': db_host,
            'PORT': db_port,
            'USER': db_user,
            'PASSWORD': db_password
        }
    }
