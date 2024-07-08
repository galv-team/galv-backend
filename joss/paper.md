---
title: 'Galv: Metadata Secretary for Battery Science'
tags:
  - Python
  - batteries
  - data science
  - metadata
  - REST API
  - management platform
authors:
  - name: Brady Planden
    corresponding: true
    orcid: 0000-0002-1082-9125
    affiliation: 1
  - name: Matt Jaquiery
    affiliation: 2
    orcid: 0000-0002-5714-1096
  - name: Martin Robinson
    orcid: 0000-0002-1572-6782
    affiliation: 2
  - name: David A. Howey
    affiliation: "1, 3"
    orcid: 0000-0002-0620-3955
affiliations:
 - name: Department of Engineering Science, University of Oxford, Oxford, UK
   index: 1
 - name: Research Software Engineering Group, Doctoral Training Centre, University of Oxford, Oxford, UK
   index: 2
 - name: The Faraday Institution, Harwell Campus, Didcot, UK
   index: 3
date: 08 July 2024
bibliography: paper.bib
---

# Summary

The `Galv` project is a data and metadata management platform for battery science.
Labs conducting battery research can use the platform to store and share data and metadata attached to their experiments.
This can include information about the battery, the experimental setup, and the results.
The platform provides a REST API for programmatic access to the data and metadata, and a web interface for manual interaction.
The platform is designed to be extensible, allowing users to define their own metadata schemas and data types.
It can be self-hosted or used as a cloud service.

# Statement of need

`Galv` is designed to address the need for a centralised data and metadata management platform for battery science.
Battery research is a rapidly growing field, with many labs conducting experiments and generating data.
This data is often stored in a variety of formats, making it difficult to share and compare results.
By providing a centralised platform for storing and sharing data and metadata, `Galv` aims to make it easier for researchers to collaborate and build on each other's work.
Futhermore, by defining a minimal structure for data, `Galv` can help researchers to ensure that their data is interoperable for meta-analysis and data science purposes.

# Architecture

Galv is composed of three components:
- The `Galv backend` is a REST API that provides programmatic access to the data and metadata stored in the platform.
- The `Galv frontend` is a web interface that allows users to interact with the data and metadata stored in the platform.
- The `Galv harvester` is a tool that can be used to automatically collect data and metadata from experiments and store it in the platform.

# Acknowledgements

- Contributors
- Funding

# References
