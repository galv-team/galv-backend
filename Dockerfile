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
RUN apt-get update && apt-get install -y \
    postgresql-client \
    build-essential libssl-dev libffi-dev python3-dev python-dev \
    libpq-dev \
    gcc \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /code
RUN mkdir /static

WORKDIR /code

COPY requirements.txt /tmp/requirements.txt
RUN set -ex && \
    pip install --upgrade pip && \
    pip install -r /tmp/requirements.txt && \
    rm -rf /root/.cache/
COPY . /code
RUN chmod +x /code/*.sh

EXPOSE 8000

WORKDIR /code/backend_django
CMD ["bash", "-c", "(/code/setup_db.sh); (/code/validation_monitor.sh &); python manage.py collectstatic --noinput; gunicorn --bind 0.0.0.0:8000 --workers 2 config.wsgi"]
