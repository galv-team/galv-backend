################################################################################
Development Guide
################################################################################

The Galv API is a Django web application using the Django Rest Framework (DRF).
Most features can be accessed via the DRF frontend for development purposes.

********************************************************************************
Running
********************************************************************************

To run the entire stack for development
================================================================================

The development stack is run using Docker Compose.
The docker compose file defines several key services, and a few utility containers.

The key stack containers are:

#. The Django backend server itself (``app``)
#. A postgres container to provide a database
#. A mailhog container to provide an SMTP service

Bring the development stack up with: ``docker-compose -f docker-compose.dev.yml up --build app``

The Django server will be available at http://localhost:8001/.

The ``app`` container is designed to allow easy substituting of its entrypoint.
This is useful for running management commands, running tests, or running the server in debug mode.
In PyCharm, for example, the app container can be added as a default Django run configuration
with the app container's Python instance as the project interpreter.

********************************************************************************
Testing
********************************************************************************

Tests are run automatically with a GitHub Action (``.github/workflows/unit-test.yml``),
and can also be run manually during development.

Backend unit tests
================================================================================

The Django backend has Django Rest Framework tests, using ``FactoryBoy`` and ``Faker``.

.. code-block:: bash

  docker-compose -f docker-compose.test.yml run --rm app_test python manage.py test

********************************************************************************
Components and Technology
********************************************************************************

This section provides a brief overview of the technology
used to implement the different parts of the project.

Docker
================================================================================

Dockerfiles are provided to run all components of this project in containers.
A docker-compose file exists to simplify starting the complete development stack
including the database, the web app and the a mailhog server.

A Docker container is also used for building the web app and its dependencies
to simplify cross platform deployment and ensure a consistent and reliable
build process.
The API server's docker container includes a simple Nginx proxy to allow
the server to handle static files and uploaded data files.

Backend server
================================================================================

The server is a `Django <https://docs.djangoproject.com/en/4.1/>`_ web application,
which uses the `Django REST Framework <https://www.django-rest-framework.org/>`_
to provide a REST API.
The following 3rd party additions are also included:

* `django-rest-knox <https://james1345.github.io/django-rest-knox/>`_

  * Token authentication

* `django-filter <https://django-filter.readthedocs.io/en/main/>`_

  * Record filtering and searching

* `django-cors-headers <https://pypi.org/project/django-cors-headers/>`_

  * CORS handling

* `drf-spectacular <https://drf-spectacular.readthedocs.io/en/latest/readme.html>`_

	* OpenAPI REST API specification

* `django-dry-rest-permissions <https://github.com/FJNR-inc/dry-rest-permissions>`_

	* Model-based permissions

There are tweaks to the basic Django systems for:

* prefilling the database with default columns and units, as well as example data values

  * ``backend_django/galv/fixtures/`` contains fixture files

    * loaded in ``backend/server.sh``

* creating superuser account

  * created by ``backend_django/galv/management/commands/create_superuser.py``

    * called in ``backend/server.sh``
    * configuration via ``.env.secret``'s ``DJANGO_SUPERUSER_PASSWORD`` entry

* handling permissions is done with a model-based approach from DRYPermissions
	* model permission code in ``backend_django/galv/models/models.py``
  * filterset code in ``backend_django/galv/permissions.py``
  *  used in ``backend_django/galv/views.py``

* there are a few places where the read and write representations of objects differ. This convenience enables:

	* presenting semi-nested representations of objects for convenience
		* A ``TruncatedHyperlinkedRelatedIdField`` is used to present a nested representation of objects
			* code in ``backend_django/galv/serializers/utils.py``
			* allows specification of fields to include
			* writes can be done with an object id or a full object representation
				* new objects cannot be created at write-time

	* support for arbitrarily extending model properties with additional fields
		* code in ``backend_django/galv/models/utils.py``

	* support for validating models against schemas
		* code in ``backend_django/galv/serializers/utils.py``

	* support for fields which are read-only unless they are being created (create_only)
		* code in ``backend_django/galv/serializers/utils.py``

	* support for Relational Data Format (RDF, JSON-LD) representations of objects
		* code in ``backend_django/galv/models/utils.py``

	* support for autocomplete objects that behave as strings in the API but are stored as objects in database
		* code in ``backend_django/galv/models/autocomplete_entries.py``
		* database objects can have JSON-LD representations

* extending ``drf-spectacular`` to play nicely with ``django-rest-knox``

  * code in ``backend_django/galv/schema.py``

* supporting dynamic storage for FileFields

  * code in ``backend_django/galv/storages.py``, ``backend_django/galv/fields.py``, and ``backend_django/galv/models/models.py``

Additionally, there are some tricks here and there in
``backend_django/galv/serializers.py`` and
``backend_django/galv/models.py``.
It's hard to say what's counterintuitive off the bat, however,
so if something confuses you and you figure it out, please document it here!

Generally speaking, most of the logic is taken care of in ``serializers.py``,
with endpoint control and documentation mostly handled in ``views.py``.
A major exception is the Harvester ``report/`` endpoint which has its
logic in ``views.py``.

Harvesters have an ``api_key`` they use to authenticate with the server.
This is created the first time the Harvester model is saved in ``models.py``.

Documentation
================================================================================

Documentation is written in `Sphinx' reStructured Text <https://www.sphinx-doc.org/en/master/usage/restructuredtext/basics.html>`_
and produced by `Sphinx <https://www.sphinx-doc.org/en/master/index.html>`_.

Documentation is located in the ``/docs/source`` directory.
It is built and served during documentation writing using the ``docs`` container.

********************************************************************************
Contributor guide
********************************************************************************

We very much welcome contributions.
Please feel free to participate in discussion around the issues listed on GitHub,
submit new bugs or feature requests, or help contribute to the codebase.

If you are contributing to the codebase, we request that your pull requests
identify and solve a specific problem, and include unit tests for code that
has been added or modified, and updated documentation if relevant.
