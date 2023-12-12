# Galv backend (REST API)
> A metadata secretary for battery science

[![Django test](https://github.com/Battery-Intelligence-Lab/galv-backend/actions/workflows/test.yml/badge.svg)](https://github.com/Battery-Intelligence-Lab/galv-backend/actions/workflows/test.yml)

The Galv backend provides a REST API powered by [Django](https://www.djangoproject.com/) and [Django REST Framework](https://www.django-rest-framework.org/).

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
