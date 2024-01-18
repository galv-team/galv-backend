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

import corsheaders.defaults
from pathlib import Path

# Build paths inside the project like this: BASE_DIR / 'subdir'.
import os

API_VERSION = "2.1.3"

try:
    USER_ACTIVATION_TOKEN_EXPIRY_S = int(os.environ.get("DJANGO_USER_ACTIVATION_TOKEN_EXPIRY_S"))
except (ValueError, TypeError):
    USER_ACTIVATION_TOKEN_EXPIRY_S = 60 * 15  # 15 minutes

BASE_DIR = Path(__file__).resolve().parent.parent

# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/4.1/howto/deployment/checklist/

ALLOWED_HOSTS = [*os.environ.get("VIRTUAL_HOST", "").split(",")]

CORS_ALLOW_HEADERS = list(corsheaders.defaults.default_headers) + [
    "X-CSRF-TOKEN"
]
CORS_ALLOWED_ORIGINS = os.environ.get("FRONTEND_VIRTUAL_HOST", "").split(",")
CORS_ALLOW_CREDENTIALS = True

# Application definition

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    "corsheaders",
    'rest_framework',
    'dry_rest_permissions',
    'django_filters',
    'knox',
    'galv.apps.GalvConfig',
    'drf_spectacular',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    "corsheaders.middleware.CorsMiddleware",
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'config.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'config.wsgi.application'


# Password validation
# https://docs.djangoproject.com/en/4.1/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]


# Internationalization
# https://docs.djangoproject.com/en/4.1/topics/i18n/

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'UTC'

USE_I18N = True

USE_TZ = True

DATA_UPLOAD_MAX_MEMORY_SIZE = 100000000


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/4.1/howto/static-files/

STATIC_URL = 'django_static/'
STATIC_ROOT = '/static/'

# Default primary key field type
# https://docs.djangoproject.com/en/4.1/ref/settings/#default-auto-field

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

SESSION_EXPIRE_AT_BROWSER_CLOSE = False

REST_FRAMEWORK = {
    # 'DEFAULT_PAGINATION_CLASS': 'galv.pagination.Unpaginatable',
    'DEFAULT_PAGINATION_CLASS': 'rest_framework.pagination.LimitOffsetPagination',
    'PAGE_SIZE': 100,
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'knox.auth.TokenAuthentication',
        'rest_framework.authentication.SessionAuthentication',
        'galv.auth.HarvesterAuthentication',
    ],
    'DEFAULT_FILTER_BACKENDS': ['django_filters.rest_framework.DjangoFilterBackend'],
    'DEFAULT_SCHEMA_CLASS': 'drf_spectacular.openapi.AutoSchema',
}
REST_KNOX = {
    'SECURE_HASH_ALGORITHM': 'cryptography.hazmat.primitives.hashes.SHA512',
    'USER_SERIALIZER': 'galv.serializers.UserSerializer',
    'AUTO_REFRESH': True,
    'AUTH_HEADER_PREFIX': 'Bearer',
    'TOKEN_LIMIT_PER_USER': 20
}
SPECTACULAR_SETTINGS = {
    'TITLE': 'Battery Data API',
    'DESCRIPTION': 'A standard API for accessing battery experiment datasets and metadata',
    'VERSION': API_VERSION,
    'CONTACT': {'email': 'martin.robinson@cs.ox.ac.uk'},
    'LICENSE': {'name': 'Apache 2.0', 'url': 'https://www.apache.org/licenses/LICENSE-2.0.html'},
    'SERVE_INCLUDE_SCHEMA': False,
    'PREPROCESSING_HOOKS': ['galv.schema.custom_preprocessing_hook'],
    'POSTPROCESSING_HOOKS': ['galv.schema.custom_postprocessing_hook'],
    'COMPONENT_SPLIT_REQUEST': True,  # handle read/writeOnly issues
}


# Mailserver
EMAIL_HOST = os.environ.get("DJANGO_EMAIL_HOST", 'mailhog')  # 'mail' is the default for docker-compose
try:
    EMAIL_PORT = int(os.environ.get("DJANGO_EMAIL_PORT", "1025"))  # '1025' is the default for smtpd
except ValueError:
    EMAIL_PORT = 1025
EMAIL_HOST_USER = os.environ.get("DJANGO_EMAIL_HOST_USER", "")
EMAIL_HOST_PASSWORD = os.environ.get("DJANGO_EMAIL_HOST_PASSWORD", "")
EMAIL_USE_TLS = os.environ.get("DJANGO_EMAIL_USE_TLS") == "True"
EMAIL_USE_SSL = os.environ.get("DJANGO_EMAIL_USE_SSL") == "True"

DEFAULT_FROM_EMAIL = os.environ.get("DJANGO_DEFAULT_FROM_EMAIL", "admin@galv")
