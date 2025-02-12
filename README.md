# Galv backend (REST API)
> A metadata secretary for battery science

[Check out the demo](https://galv-demo.fly.dev)

[![GitHub Releases](https://img.shields.io/github/v/release/galv-team/galv-backend)](https://github.com/galv-team/galv-backend/releases/latest)
[![Docker image](https://ghcr-badge.egpl.dev/galv-team/galv-backend/latest_tag?color=%2344cc11&ignore=latest&label=image&trim=0)](https://github.com/galv-team/galv-backend/pkgs/container/galv-backend)

[![CI workflows](https://github.com/galv-team/galv-backend/actions/workflows/configure-workflows.yml/badge.svg)](https://github.com/galv-team/galv-backend/actions/workflows/configure-workflows.yml)
[![pre-commit.ci status](https://results.pre-commit.ci/badge/github/galv-team/galv-backend/develop.svg)](https://results.pre-commit.ci/latest/github/galv-team/galv-backend/develop)

> API client libraries:
>
> [![NPM Downloads](https://img.shields.io/npm/dm/%40galv%2Fgalv)](https://www.npmjs.com/package/@galv/galv)
> [![PyPI - Downloads](https://img.shields.io/pypi/dm/galv)](https://pypi.org/project/galv/)


The Galv backend provides a REST API powered by [Django](https://www.djangoproject.com/) and [Django REST Framework](https://www.django-rest-framework.org/).

## Galv Project
- [**Backend**](https://github.com/galv-team/galv-backend)
- [Frontend](https://github.com/galv-team/galv-frontend)
- [Harvester](https://github.com/galv-team/galv-harvester)

For more complete documentation, see the
[Galv Server documentation](https://galv-team.github.io/galv-backend/).


## Demo instance

There is a public demo instance of Galv (reset every week) available at [galv-demo.fly.dev](https://galv-demo.fly.dev).

## Deploying

The Galv backend is deployed using [Docker](https://www.docker.com/).
You can deploy the Galv backend in a number of ways.

### Docker image

Each [release](/galv-team/galv-backend/releases) is accompanied by a [Docker image](/galv-team/packages?repo_name=galv-backend).
The latest stable version is tagged as `latest`.
You can acquire the image by pulling it from GitHub Packages:

```bash
docker pull ghcr.io/galv-team/galv-backend:latest
```

You can then run the image using the following command:

```bash
docker run -p 8001:80 ghcr.io/galv-team/galv-backend:latest
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
Tags that match `v\d+\.\d+\.\d+` will be tagged as `latest` when released.
Tags with a suffix, e.g. `v1.0.0-beta`, will not be tagged as `latest`.

There is a fairly complex workflow that will update the documentation for all versions when a new version is released.
This workflow is defined in `.github/workflows/docs.yml`, with help from `docs/build_docs.py`.

## Testing

Tests are most easily run using the provided Dockerfile and docker-compose.yml files.
The docker-compose.yml file will start a postgres database and run the tests.
The following command will run the tests:

```bash
docker-compose run --rm app_test
```

## Publishing

### Versioning

We use [Semantic Versioning](https://semver.org/).
When you make a change, you should update the `API_VERSION` in `galv_backend/config/settings_base.py`.

If you update the documentation, you should also update the `release` version in `docs/source/conf.py` and add the new version tag to `docs/tags.json`.

These versions should all use clean SemVer versioning, i.e. `v*.*.*`.

Published versions should be released incrementally.
**The Actions workflows will assume there exists a clean version tag for each release, e.g. v1.2.3-rc4 will assume v1.2.2 exists.**

### Tagged releases

When you want to release a new version, using the GitHub Actions workflow, create a new tag.
The tag should be a SemVer version, optionally with a qualifier (e.g. `v1.2.3-alpha`).

Make sure the tag's version matches the `API_VERSION` in `galv_backend/config/settings_base.py`.

E.g. if your `API_VERSION` is `1.2.3` you can create tags like `v1.2.3`, `v1.2.3-alpha`, `v1.2.3-rc1`, etc.

#### Release candidates

Tags that end with `-rc#` will be treated as release candidates.

When you create a release candidate, the GitHub Actions will deploy the candidate version to the `staging` server.

This deployment will run the migrations, etc. so we can detect if something is likely to break in production.

#### Demo version

The `demo` instance is published every week.
It will use the `DEMO_BACKEND_VERSION` listed in `.github/workflows/demo.yml` as the version to deploy.

You can also trigger the workflow manually, or by pushing a commit that updates the demo version in the demo workflow file.

### GitHub Actions

We use a fairly complicated GitHub Actions flow to ensure we don't publish breaking changes.
The `configure-workflows.yml` action is run on every push to the repository, and it determines which workflows to run based on the branch/tag and the contents of the repository.

When you push to a branch, the following actions are considered:
- Configure workflows
- Run tests (A)
- Build and publish documentation (B)
- Build and publish OpenAPI spec (C)
- Build and publish API client libraries (C)
- Build and publish Docker images (A)
- Issue a GitHub release (A)
- Deploy staging instance (D)
- Deploy demo instance (E)

The triggers are:
A. changes in `backend_django`, or other code files like `requirements.txt` or `Dockerfile`
B. changes in `docs`
C. B & changes to the OpenAPI spec (i.e. the specifications are not equivalent)
D. tags that match `v*.*.*-rc#`
E. changes to the `DEMO_BACKEND_VERSION` in `.github/workflows/demo.yml`

N.B. Changes are calculated vs the previous release, not the previous commit.

#### Requirements:

The `configure-workflows.yml` action also checks a couple of requirements:

- The version in the tag must match the `API_VERSION` in `galv_backend/config/settings_base.py`.
- If the tag is a release (v*.*.*), there must not be an existing release for the same version.
- If there are breaking changes in the OpenAPI spec, the tag must be a major version.

To run the OpenAPI compatibility checks locally, run the following command:

```bash
docker-compose run --rm check_spec
```

You can optionally specify the `REMOTE_SPEC_SOURCE` environment variable to check against a different version of the galv-spec.

```bash
cp my_spec.json .dev/spec
# .dev/spec is mounted as a volume at /spec in the container
docker-compose run --rm -e REMOTE_SPEC_SOURCE=/spec/my_spec.json check_spec
```

## Releasing with Fly.io

We use Fly.io to host a few instances.
The configuration files are `fly.*.toml` in the root of the repository.
To deploy to Fly.io, you will need to install the Fly CLI and authenticate.
Once done, use `fly deploy --app <app-name> --config <config-file>` to deploy.
E.g. for the Battery Intelligence Lab staging instance, we would use:
```bash
fly deploy --app galv-stage-backend --config fly.stage.toml
```

You'll have to create and attach the Postgres DB to the app manually.

```bash
fly postgres create --name <app-name>-db --org <org-name-if-applicable> --vm-size shared-cpu-2x
fly postgres attach <app-name>-db --app <app-name>
```

Attaching will set the `DATABASE_URL` environment variable in the app to the connection string for the database.
It gets set as a secret so it's not visible in the logs.

You may need to set other secrets using `fly secrets set --app <app-name> --config <config-file> <SECRET_NAME>=<SECRET_VALUE>`
if you're using AWS S3 for storage, etc.
