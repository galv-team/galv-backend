# Galv backend (REST API)

The Galv backend provides a REST API powered by [Django]() and [Django REST Framework]().

## Deploying

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
