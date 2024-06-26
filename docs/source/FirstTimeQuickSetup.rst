######################################################################################
First Time Quick Setup
######################################################################################

This section describes how to set up the system for the first time. 
It is assumed you are logged into the server machine that you 
wish to use, using the user account that you want to run the server with. 
The entire application has been dockerised, so can in theory be used on 
any major operating system with minimal modification.

**************************************************************************************
Deploying on fly.io
**************************************************************************************

The Galv team use fly.io to deploy the Galv application.
This is a cloud service that allows you to deploy docker containers to a server.

You can find the example configuration file for fly.io in the repository root directory
``fly.toml``. This file is used to configure the deployment of the Galv application.

To run the application it's easiest to use the prebuilt container which accompanies
each release on GitHub.
The containers are stored in GitHub's Container Registry.

To launch with fly.io, you will need to:

1. Install the fly.io CLI tool, which can be found `here <https://fly.io/docs/getting-started/installing-fly/>`_.
2. Log in to the fly.io CLI tool using the command ``fly login``.
3. Create a new postgres database using the command ``fly postgres create``. The name you give it will be needed in step 5.
4. Create a new application using the command ``fly apps create``. The name you give it will be needed in step 5.
5. Attach the postgres database to the application using the command ``fly postgres attach <postgres_app_name> --app <galv_app_name>``.
6. Set the environment variables by modifying the ``fly.toml`` file. Most variables have sensible defaults.
  You will need to ensure that the ``VIRTUAL_HOST_ROOT`` is set to the domain name you wish to use - e.g. ``galv-app.fly.dev``.
  You will also need to ensure that the ``FRONTEND_VIRTUAL_HOST`` is set to the domain name you wish to use for the frontend - e.g. ``galv-frontend.fly.dev``.
7. Set the secret environment variables by running the command ``fly secrets set DJANGO_SECRET_KEY=<secret_key>``.
  Do the same for the superusers's password with ``fly secrets set DJANGO_SUPERUSER_PASSWORD=<superuser_password>``.
8. Launch the application using the command ``fly deploy``.
  This will launch the latest version of the Galv backend on the fly.io server by looking for the container image
  in the GitHub Container Registry. It is possible to build your own version from the source code.

**************************************************************************************
Deploying on EC2 or other cloud services - single service
**************************************************************************************

You can deploy Galv on any cloud service that supports docker containers.
The following instructions are for deploying on an AWS EC2 instance.

1. Launch an EC2 instance with the Amazon Linux 2 AMI.
2. SSH into the instance.
3. Install docker.
.. code-block:: shell

  sudo yum update -y
  sudo amazon-linux-extras install docker
  sudo service docker start
  sudo usermod -a -G docker ec2-user

4. Create a .env file with the environment variables you need.
  This can have both the normal and secret environment variables.
  You can use the .env file in the repository as a template.
  At the very least, you will need to set:
  * DJANGO_SECRET_KEY
  * DJANGO_SUPERUSER_PASSWORD
  * Postgres connection details using either POSTGRES_* variables or DATABASE_URL
  * VIRTUAL_HOST_ROOT
  * FRONTEND_VIRTUAL_HOST
5. Build the container from the GitHub Container Registry.
.. code-block:: shell

  docker run -d --env-file .env -p 80:80 ghcr.io/galv-team/galv-backend:latest

**************************************************************************************
Installing required tools
**************************************************************************************

You need to have ``docker``, ``docker-compose`` and ``git`` installed and available on your
command-line. 

You can find installation instructions for ``docker`` on all major operating systems
`here <https://docs.docker.com/engine/install/>`_, and for ``docker-compose``
`here <https://docs.docker.com/compose/install/>`_. For linux hosts, it is useful to be
able to use ``docker`` as a non-root user, and you can find instructions on how to set
this up `here <https://docs.docker.com/engine/install/linux-postinstall/>`_. If you don't,
note that you will need to add ``sudo ...`` in front of every ``docker`` and
``docker-compose`` command listed below.

Installation instructions for ``git`` for all major OSs can be found
`here <https://git-scm.com/book/en/v2/Getting-Started-Installing-Git>`_.


Get the galv source code
=======================================================================================

First you will need to clone the galv repository using ``git``:

.. code-block:: bash

	git clone https://gitlab.com/galv-team/galv-project/galv.git
	cd galv


Setup environment variables
=======================================================================================

The Galv project uses two ``.env`` files, ``.env`` and ``.env.secret``.

You will already have a ``.env`` file in the repository you cloned, with sensible defaults.

If you're running a **production deployment**, you will want to set the value of the
``VIRTUAL_HOST_ROOT`` to your domain name, e.g. ``VIRTUAL_HOST_ROOT=example.com``.
This will serve the Galv web application from the root of your domain,
e.g. at ``http://example.com/``; and the API from the subdomain, e.g. ``http://api.example.com``.
You will likely also want to enable HTTPS, for which we use LetsEncrypt to generate SSL certificates.
By default, the staging (test) server is used, which generates certificates that are not trusted by browsers.
When your production setup appears to work correctly, you can switch to fetching real certificates
by setting ``LETSENCRYPT_TEST=false`` and restarting the nginx-proxy container.

If you wish to change where the database is saved, you can change the first entry
in ``.env``, ``GALV_DATA_PATH`` to the directory where you want the postgres database.

Create ``.env.secret``
=======================================================================================

The second ``.env`` file is a secrets file.
This is not included because you should come up with your own secret values for the
entries within it. 
Create the file and edit it so that it has the following keys:

* DJANGO_SECRET_KEY
* DJANGO_SUPERUSER_PASSWORD
* POSTGRES_PASSWORD

All of these values should be unguessable secure passwords. 
DJANGO_SECRET_KEY should be very long and complex, consider 60+ characters
with a mixture of special characters (avoid $), upper- and lower-case letters, 
and numbers.
The only one of these you will need to use again will be the superuser password.

If you would like the Django superuser to have a name that is not 'admin', 
you can also specify DJANGO_SUPERUSER_USERNAME.

.. code-block:: shell

	vi .env.secret  # could also use nano, emacs, etc.


Build docker images (only when upgrading to a new version of galv)
=======================================================================================

If you have previously installed and run galv you might already have old docker
images already built. To rebuild the images, run the following command:

.. code-block:: bash

	docker-compose build

**************************************************************************************
Running Galv
**************************************************************************************

You can run the galv server and web application frontend using the following
``docker-compose`` command from the root folder of the repository.

.. code-block:: bash

	docker-compose up

Now view the 'localhost' IP address `http://127.0.0.1/ <http://127.0.0.1/>`_ in your
browser and you should see the Galv login page.
This is the web frontend.
If you wish to use the frontend from another machine, 
use the IP address or URL of the server instead.

Creating a user account
========================================================================================

It's not a good idea to do everything with the Django superuser, 
so create a new account on the login page. 
You'll see that you get a message telling you that the account 
needs to be approved by an existing account.

* Refresh the page, and login using the _superuser_ credentials.
* Once logged in, go to the bottom tab in the menu (Approve Users), and click the button next to your new user account
* Now, click the logout button in the top right, and log back in with your new user account

**************************************************************************************
Setting up a Harvester
**************************************************************************************

Harvesters are set up using a part of the code of the main Galv repository.
The first step, then, is to log onto the machine that will run the harvesters and 
clone the repository again.
If you are using the same server for the harvester and the rest of Galv,
you can skip this step.

.. code-block:: bash

	git clone https://gitlab.com/galv-team/galv-project/galv.git
	cd galv


Next, launch the harvester container, specifying the Harvester's docker-compose configuration file:

.. code-block:: shell

	docker-compose -f docker-compose.harvester.yml run harvester bash
	python start.py

This will launch into an interactive shell which will guide you through the Harvester setup process.

First, you'll be asked for the Galv server URL.
If you're running on the same server as the Galv server, this will be ``http://app``,
otherwise it will be the path you entered above to connect to the web frontend, 
but using the ``api`` subdomain. So if you went to ``http://example.com``, go to ``http://api.example.com``.

Next, you'll be asked for your credentials, either as an API token or a username/password.
You'll need to set up a Lab in the Galv web frontend first, and then create a Lab admin user account.

Next, you'll be asked to specify a name for the new Harvester. 

The Harvester will register itself with the Galv server and begin to monitor for data files.
Of course, it currently has no directories to monitor, so the last step is to
go to the web frontend and configure at least one monitored path for the Harvester.

Monitored Paths belong to Teams, so create a Team in the Harvester's Lab if you haven't done so already.
You should add a user (it can be yourself) to the Team, either as an admin or a regular user.

With the Team account, open up the web frontend in a browser and select the 'Harvesters' tab.
Click on the magnifying glass icon to see details for your new Harvester.
Enter a path for the Harvester to monitor (relative to the Harvester's system), 
and click the plus icon to save your new path.

The Harvester will now crawl the directory, observing files and importing them
when they have been stable for a sufficiently long time.

**************************************************************************************
Maintenance
**************************************************************************************

To run the server in detached mode (i.e. run containers in the background) using the 
``-d`` option

.. code-block:: bash

	docker-compose up -d


To start the server side system again after it has been stopped simply run 
``docker-compose up`` in the root folder.

A template SystemD service file is included in the repository root directory 
``galv.service`` that can be used to automatically start the system on Linux servers.


If Harvesters go down, they can be restarted.
.. code-block:: shell

	docker-compose -f docker-compose.harvester.yml run harvester python start.py --restart

