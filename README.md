# Galv backend (REST API)
> A metadata secretary for battery science

[![CI Tests](https://github.com/Battery-Intelligence-Lab/galv-backend/actions/workflows/test.yml/badge.svg)](https://github.com/Battery-Intelligence-Lab/galv-backend/actions/workflows/test.yml)
[![Release](https://github.com/Battery-Intelligence-Lab/galv-backend/actions/workflows/issue-release.yml/badge.svg)](https://github.com/Battery-Intelligence-Lab/galv-backend/actions/workflows/issue-release.yml)

The Galv backend provides a REST API powered by [Django](https://www.djangoproject.com/) and [Django REST Framework](https://www.django-rest-framework.org/).

## Galv Project
- [Specification](/Battery-Intelligence-Lab/galv-spec)
- [**Backend**](/Battery-Intelligence-Lab/galv-backend)
- [Frontend](/Battery-Intelligence-Lab/galv-frontend)
- [Harvester](/Battery-Intelligence-Lab/galv-harvester)

## Deploying

The Galv backend is deployed using [Docker](https://www.docker.com/).
It can be deployed using the Dockerfile provided in this repository.

You should ensure that all variables in the `.env` file are set correctly before deploying.
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

### Setting up in PyCharm

To set up the development environment in PyCharm, make sure there's a project interpreter set up for the Docker container.
Once you have that, create a Django server configuration with the following settings:
- Host: `0.0.0.0` (this allows you to reach the server from your host machine)
- Port: `80` (**not** `8001` - this is the port on the Docker container, not the host machine)

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
