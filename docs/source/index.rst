.. Galv documentation master file, created by
   sphinx-quickstart on Thu Mar  9 11:40:09 2023.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

.. figure:: img/Galv-logo-tag.png
   :alt: Galv logo
   :target: https://galv-team.github.io/galv-backend/
   :scale: 50%

The `Galv project <https://github.com/galv-team/>`_
is a web platform for battery data analysis and metadata management.
This documentation provides a guide to Galv's API, known as the backend.

The Galv backend is a REST API that provides endpoints for managing battery data and metadata.
It runs in concert with a frontend and a harvester, which are separate projects.
The frontend is a web application that provides a user interface for interacting with the backend,
while the harvester is a Python package that collects battery data from various sources.

.. toctree::
   :maxdepth: 2
   :caption: Contents:

   FirstTimeQuickSetup
   DevelopmentGuide


Frontend and Harvester documentation
--------------------------------------------------------------------------------------

The front and harvester documentation can be found at the following links:

* `Galv Frontend <https://galv-team.github.io/galv-frontend/>`_
* `Galv Harvester <https://pypi.org/project/galv-harvester/>`_


Indices and tables
======================================================================================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
