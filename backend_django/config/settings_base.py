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

API_VERSION = "2.4.5-dev"

try:
    USER_ACTIVATION_TOKEN_EXPIRY_S = int(os.environ.get("DJANGO_USER_ACTIVATION_TOKEN_EXPIRY_S"))
except (ValueError, TypeError):
    USER_ACTIVATION_TOKEN_EXPIRY_S = 60 * 15  # 15 minutes

try:
    USER_PW_RESET_TOKEN_EXPIRY_S = int(os.environ.get("DJANGO_USER_PW_RESET_TOKEN_EXPIRY_S"))
except (ValueError, TypeError):
    USER_PW_RESET_TOKEN_EXPIRY_S = 60 * 15  # 15 minutes

BASE_DIR = Path(__file__).resolve().parent.parent

# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/4.1/howto/deployment/checklist/

ALLOWED_HOSTS = [*os.environ.get("VIRTUAL_HOST", "").split(",")]

CORS_ALLOW_HEADERS = list(corsheaders.defaults.default_headers) + [
    "X-CSRF-TOKEN",
    "Galv-Storage-No-Redirect"
]
CORS_EXPOSE_HEADERS = [
    "Galv-Storage-Redirect-URL",
    "Content-Disposition",
]
CORS_ALLOWED_ORIGINS = [
    *os.environ.get("FRONTEND_VIRTUAL_HOST", "").split(","),
    "https://galv-team.github.io"
]
CORS_ALLOW_CREDENTIALS = True

# Application definition

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'django.contrib.postgres',
    "corsheaders",
    "debug_toolbar",
    # "cachalot",
    'rest_framework',
    'dry_rest_permissions',
    'django_filters',
    'knox',
    'galv.apps.GalvConfig',
    'drf_spectacular',
    # "django_snakeviz_profiling",
]

MIDDLEWARE = [
    # "django_snakeviz_profiling.SnakevizProfilingMiddleware",
    'django.middleware.security.SecurityMiddleware',
    "corsheaders.middleware.CorsMiddleware",
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    "debug_toolbar.middleware.DebugToolbarMiddleware",
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]
SNAKEVIZ_PROFILING = "PLEASE_PROFILE_REQUESTS"

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
    'DEFAULT_FILTER_BACKENDS': [
        'django_filters.rest_framework.DjangoFilterBackend',
        'rest_framework.filters.SearchFilter',
        'rest_framework.filters.OrderingFilter',
    ],
    'DEFAULT_SCHEMA_CLASS': 'drf_spectacular.openapi.AutoSchema',
    'DEFAULT_RENDERER_CLASSES': [
        'rest_framework.renderers.JSONRenderer',
        'rest_framework.renderers.BrowsableAPIRenderer',
        'galv.renderers.BinaryRenderer',
    ],
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

# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/4.1/howto/static-files/

# Amazon Web Services S3 storage settings
# These apply for static files and media files only.
# Data files may be uploaded to S3, but Labs have to configure their own S3 access settings.
AWS_S3_REGION_NAME = os.environ.get("DJANGO_AWS_S3_REGION_NAME")
AWS_STORAGE_BUCKET_NAME = os.environ.get(
    "DJANGO_AWS_STORAGE_BUCKET_NAME",
    os.environ.get("BUCKET_NAME")  # compatability with Fly's Tigris service
)
AWS_DEFAULT_ACL = os.environ.get("DJANGO_AWS_DEFAULT_ACL", "private")
AWS_S3_OBJECT_PARAMETERS = {
    "CacheControl": "max-age=2592000",
}
AWS_S3_SIGNATURE_VERSION = 's3v4'
AWS_S3_CUSTOM_DOMAIN = os.environ.get(
    "AWS_ENDPOINT_URL_S3",  # for Fly's Tigris service
    f"https://{AWS_STORAGE_BUCKET_NAME}.s3.amazonaws.com"
)
DATA_STORAGE_UPLOAD_URL_EXPIRY_S = int(os.environ.get("DJANGO_DATA_STORAGE_UPLOAD_URL_EXPIRY_S", 60 * 60))  # 1 hour

# If Labs exceed their storage quota (or if the quota is set to 0),
# they can still define their own S3 storage settings to save to the S3 cloud.
LAB_STORAGE_QUOTA_BYTES = int(os.environ.get("DJANGO_LAB_STORAGE_QUOTA_BYTES", 10 ** 8))  # 100 MB
# If this is set to True, Labs can use our S3 storage to store their data files.
# This is still subject to the LAB_STORAGE_QUOTA_BYTES limit.
LABS_USE_OUR_S3_STORAGE = os.environ.get("DJANGO_LABS_USE_OUR_S3_STORAGE") == "True"

# Static, media, and data files are served from S3 if S3 is configured
# Otherwise, they are served from the local filesystem
STATICFILES_LOCATION = "static"
MEDIAFILES_LOCATION = "media"
DATAFILES_LOCATION = "data"

S3_ENABLED = bool(AWS_S3_REGION_NAME) and bool(AWS_STORAGE_BUCKET_NAME) and bool(AWS_DEFAULT_ACL)
if S3_ENABLED and not os.environ.get("AWS_SECRET_ACCESS_KEY"):
    print(os.system('env'))
    raise ValueError("AWS settings are incomplete - missing AWS_SECRET_ACCESS_KEY")

STORAGES = {}

if S3_ENABLED and os.environ.get("DJANGO_STORE_MEDIA_FILES_ON_S3", False) == "True":
    STORAGES["default"] = {"BACKEND": "galv.storages.MediaStorage"}  # for media
    MEDIA_URL = f"{AWS_S3_CUSTOM_DOMAIN}/{MEDIAFILES_LOCATION}/"
else:
    STORAGES["default"] = {
        "BACKEND": "django.core.files.storage.FileSystemStorage",
        "LOCATION": f"/{MEDIAFILES_LOCATION}"
    }
    MEDIA_ROOT = f"/galv_files/{MEDIAFILES_LOCATION}"
    MEDIA_URL = f"/{MEDIAFILES_LOCATION}/"

if S3_ENABLED and os.environ.get("DJANGO_STORE_STATIC_FILES_ON_S3", False) == "True":
    STORAGES["staticfiles"] = {"BACKEND": "galv.storages.StaticStorage"}  # for static
    STATIC_URL = f"{AWS_S3_CUSTOM_DOMAIN}/{STATICFILES_LOCATION}/"
    STATICFILES_DIRS = [f"/{STATICFILES_LOCATION}"]
else:
    STORAGES["staticfiles"] = {"BACKEND": "django.contrib.staticfiles.storage.StaticFilesStorage"}
    STATIC_ROOT = f"/galv_files/{STATICFILES_LOCATION}"
    STATIC_URL = f"/{STATICFILES_LOCATION}/"

# Data storage is always dynamic depending on _StorageType models,
# so doesn't need to be configured in STORAGES.
DATA_ROOT = f"/galv_files/{DATAFILES_LOCATION}"
DATA_URL = f"/{DATAFILES_LOCATION}/"

MAX_PNG_PREVIEW_SIZE = int(os.environ.get("DJANGO_MAX_PNG_PREVIEW_SIZE_BYTES", 10 ** 5))  # 100 KB

# Harvester report constants
# These definitions should be kept in sync with the definitions in the harvester program
HARVESTER_TASK_FILE_SIZE = 'file_size'
HARVESTER_TASK_IMPORT = 'import'
HARVESTER_STATUS_SUCCESS = 'success'
HARVESTER_STATUS_ERROR = 'error'
HARVEST_STAGE_FILE_METADATA = 'file metadata'
HARVEST_STAGE_DATA_SUMMARY = 'data summary'
HARVEST_STAGE_UPLOAD_PARQUET = 'upload parquet partitions'
HARVEST_STAGE_UPLOAD_COMPLETE = 'upload complete'
HARVEST_STAGE_UPLOAD_PNG = 'upload png'
HARVEST_STAGE_COMPLETE = 'harvest complete'
HARVEST_STAGE_FAILED = 'harvest failed'
