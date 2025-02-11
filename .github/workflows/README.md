# Galv Backend Actions

The Galv backend uses actions to:

- Configure workflows
- Run tests
- Build and publish documentation
- Build and publish OpenAPI spec
- Build and publish API client libraries
- Build and publish Docker images
- Issue a GitHub release
- Deploy staging instance
- Deploy demo instance

## Structure

Determining what workflows to run, and when, is governed by the `configure-workflows.yml` action.

The `configure-workflows.yml` action is run on every push to the repository, and it determines which workflows to run based on the branch/tag and the contents of the repository.

It will check:

- Which files have changed
- What branch/tag the push is on
- Whether the branch/tag is a version tag, and if so whether it matches `API_VERSION`
- Whether the tag is a release (v*.*.*) or release candidate (v*.*.*-rc#)
- Whether the OpenAPI spec has changed
- Whether the OpenAPI spec has breaking changes

Based on this information, it will enable or disable workflows.

The `configure-workflows.yml` action can be called with `github_dispatch` to manually specify any of the fields.

### Potential failures

- If the tag/branch is semver and the clean version does not match the `API_VERSION` in `backend_django/config/settings_base.py`, the action will fail.
- If the tag/branch is a release (v*.*.*) and one already exists for the same version, the action will fail.
- If there are breaking OpenAPI changes and the branch/tag is not a major version, the action will fail.

## Workflows

| Workflow                   | Description                                                                                                     |
|----------------------------|-----------------------------------------------------------------------------------------------------------------|
| CI tests                   | Run tests on every push to the repository where `backend_django`, `requirements`, or `Dockerfile`s have changed |
| Build docs                 | Build and publish documentation on every push to the repository where `docs` have changed                       |
| OpenAPI Spec               | Build and publish API client libraries on every push to the repository OpenAPI spec has changed                 |
| Build API client libraries | Build and publish API client libraries on every push to the repository OpenAPI spec has changed                 |
| Build Docker image         | Build and publish Docker image that passes CI tests                                                             |
| GitHub Release             | Issue a GitHub release                                                                                          |
| Deploy staging             | Deploy staging instance on every push to `-rc#` tags or branches                                                |
| Deploy demo                | Deploy demo instance on every push to `demo` or `demo-*` branches, and on a weekly schedule                     |
