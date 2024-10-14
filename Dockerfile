# SPDX-License-Identifier: BSD-2-Clause
# Copyright  (c) 2020-2023, The Chancellor, Masters and Scholars of the University
# of Oxford, and the 'Galv' Developers. All rights reserved.

ARG PYTHON_VERSION=3.10-slim-bullseye

FROM python:${PYTHON_VERSION}

ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1
ENV DJANGO_SETTINGS_MODULE config.settings

# Install postgresql-client for healthchecking
# install psycopg2 dependencies.
# Install NGINX for file serving
# We can't use WhiteNoise because we need to use xAccelRedirect to allow Django to verify permissions on files
RUN apt-get update && apt-get install -y \
    postgresql-client \
    build-essential libssl-dev libffi-dev python3-dev python-dev \
    libpq-dev \
    gcc \
    nginx \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /code
RUN mkdir -p /galv_files/static
RUN mkdir -p /galv_files/media
RUN mkdir -p /galv_files/data
RUN mkdir -p /var/log/galv

WORKDIR /code

COPY requirements.txt /tmp/requirements.txt
RUN set -ex && \
    pip install --upgrade pip && \
    pip install -r /tmp/requirements.txt && \
    rm -rf /root/.cache/
COPY . /code
RUN chmod +x /code/*.sh

# For NGINX
COPY nginx.conf /etc/nginx/nginx.conf
RUN nginx -t
EXPOSE 80

WORKDIR /code/backend_django

ENTRYPOINT ["/code/server.sh"]
