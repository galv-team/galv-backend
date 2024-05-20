# Galv backend (REST API)
> A metadata secretary for battery science

[![CI tests](https://github.com/galv-team/galv-backend/actions/workflows/test.yml/badge.svg)](https://github.com/galv-team/galv-backend/actions/workflows/test.yml)
[![Build docs](https://github.com/galv-team/galv-backend/actions/workflows/docs.yml/badge.svg)](https://github.com/galv-team/galv-backend/actions/workflows/docs.yml)
[![Release](https://github.com/galv-team/galv-backend/actions/workflows/issue-release.yml/badge.svg)](https://github.com/galv-team/galv-backend/actions/workflows/issue-release.yml)

The Galv backend provides a REST API powered by [Django](https://www.djangoproject.com/) and [Django REST Framework](https://www.django-rest-framework.org/).

## Galv Project
- [**Backend**](https://github.com/galv-team/galv-backend)
- [Frontend](https://github.com/galv-team/galv-frontend)
- [Harvester](https://github.com/galv-team/galv-harvester)

## Deploying

The Galv backend is deployed using [Docker](https://www.docker.com/).
You can deploy the Galv backend in a number of ways.

### Docker image

Each [release](/galv-team/galv-backend/releases) is accompanied by a [Docker image](/galv-team/packages?repo_name=galv-backend).
You can acquire the image by pulling it from GitHub Packages:

```bash
docker pull ghcr.io/battery-intelligence-lab/galv-backend:latest
```

You can then run the image using the following command:

```bash
docker run -p 8001:80 ghcr.io/battery-intelligence-lab/galv-backend:latest
```

You will need to add in a database and set the environment variables appropriately.
You will also need to add environment variables as detailed [below](#Envvars).

### Docker Compose

Galv can be deployed using the Dockerfile provided in this repository.
Example usage is provided in the [docker-compose.yml](/galv-team/galv-backend/blob/main/docker-compose.yml) file.
This is generally for development, however, so you will need to add a database and set the [environment variables](#Envvars) appropriately.

## Envvars

You should ensure that all environment variables in the `.env` file are set correctly before deploying.
These variables can be set by editing and including the `.env` file, by setting them in the environment, 
or by setting them via a hosting platform's interface.

## Development

Development is most easily done by using the provided Dockerfile and docker-compose.yml files.  The docker-compose.yml file will start a postgres database and the Django server.  The Django server will automatically reload when changes are made to the code.
The following command will start the server:

```bash
docker-compose up app
```

The server will be available at http://localhost:8001.

### Gotchas

- The docker-compose file only mounts the `galv-backend` directory, so if you add a new file or directory, to the project root, you will need to rebuild the container.
- The `app` container is started with `server.sh`. If this file has acquired non-LF line endings, the container will report that it can't be found when starting.

### Setting up in PyCharm

To set up the development environment in PyCharm, make sure there's a project interpreter set up for the Docker container.
Once you have that, create a Django server configuration with the following settings:
- Host: `0.0.0.0` (this allows you to reach the server from your host machine)
- Port: `80` (**not** `8001` - this is the port on the Docker container, not the host machine)

## Documentation

Documentation is generated using [Sphinx](https://www.sphinx-doc.org/en/master/).
To make it easy to develop documentation, a Dockerfile is provided that will build the documentation and serve it using a webserver.
It should refresh automatically when changes are made to the documentation.

The docs container is started with `docker-compose up docs`. 
By default, it will serve at http://localhost:8005.

### Versioning

The documentation supports multiple versions. 
To add a new version, add a new entry to `docs/tags.json`.
These tags must be in the format `v*.*.*` and must be available as a git tag.

There is a fairly complex workflow that will update the documentation for all versions when a new version is released.
This workflow is defined in `.github/workflows/docs.yml`, with help from `docs/build_docs.py`.

## Testing

Tests are most easily run using the provided Dockerfile and docker-compose.yml files.  
The docker-compose.yml file will start a postgres database and run the tests.  
The following command will run the tests:

```bash
docker-compose run --rm app_test
```

## GitHub Actions

We use a fairly complicated GitHub Actions flow to ensure we don't publish breaking changes.
When you push to a branch, we do the following:
- Run the tests
  - If tests succeed, and branch or tag is `v*.*.*`, we check compatibility with the previous version
    - If the API_VERSION in `backend_django/config/settings_base.py` is different to the branch/tag name, fail.
    - If incompatible, and we're not publishing a new major version, fail.
    - Create clients for TypeScript (axios) and Python
    - Create a docker image hosted on GitHub Packages
    - Create a GitHub release

To run the compatibility checks locally, run the following command:

```bash
docker-compose run --rm check_spec
```

You can optionally specify the `REMOTE_SPEC_SOURCE` environment variable to check against a different version of the galv-spec.

```bash
cp my_spec.json .dev/spec
# .dev/spec is mounted as a volume at /spec in the container
docker-compose run --rm -e REMOTE_SPEC_SOURCE=/spec/my_spec.json check_spec
```
