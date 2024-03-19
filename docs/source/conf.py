# Configuration file for the Sphinx documentation builder.
#
# For the full list of built-in configuration values, see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html
import json
import os

# -- Project information -----------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#project-information

project = 'Galv'
copyright = '2023, Oxford RSE'
author = 'Oxford RSE'
release = '2.1.22'

# -- General configuration ---------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#general-configuration

extensions = []

templates_path = ['_templates']
exclude_patterns = []



# -- Options for HTML output -------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#options-for-html-output

html_theme = 'sphinx_rtd_theme'
html_static_path = ['_static']

# -- Script from codingwiththomas.com -------------------------------------------------
# https://www.codingwiththomas.com/blog/my-sphinx-best-practice-for-a-multiversion-documentation-in-different-languages

# get the environment variable build_all_docs and pages_root
build_all_docs = os.environ.get("build_all_docs")
pages_root = os.environ.get("pages_root", "")

# if not there, we dont call this
if build_all_docs is not None:
  # we set the html_context with current version and versions from json file
  html_context = {
    'current_version' : os.environ.get("current_version", "no-curent-version-envvar"),
    'versions' : json.load(open("../tags.json", "r")),
  }
