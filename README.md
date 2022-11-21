# docker-pytest-bdd

Testing applications using [pytest-bdd].

Simplify running pytest-bdd in docker/docker-compose.

## Example

use it as base image

    FROM dintero/docker-pytest-bdd
    COPY example /example
    WORKDIR /example
    CMD pytest

run with volume mount

    docker run \
      -v $(pwd)/example:/example \
      -w /example \
      dintero/docker-pytest-bdd \
        pytest -vv \
          --gherkin-terminal-reporter \
          --cucumberjson-expanded

    # run pytest -h to get help on all options
    docker run dintero/docker-pytest-bdd pytest -h

    # only run test with match the given substring expression
    docker run \
      -v $(pwd)/example:/example \
      -w /example \
      dintero/docker-pytest-bdd \
        pytest -vv \
          --gherkin-terminal-reporter \
          --cucumberjson-expanded \
          -k post

## Installed Libraries

The docker image installs many useful libraries
for testing REST APIs with pytest-bdd.

 - boto3
 - [bravado_core]: support for the OpenAPI Specification v2.0. (Swagger 2)
 - PyCryptodome
 - pytcodestyle
 - [PyJWT]: JSON Web Token implementation in Python
 - pytest-bdd
 - pytest-parallel
 - pytest
 - [Requests]: HTTP for Humans

See the [requirements.txt] for complete list of libraries installed by the [Dockerfile].

[Dockerfile]: https://github.com/dintero/docker-pytest-bdd/blob/master/Dockerfile
[pytest-bdd]: https://pypi.python.org/pypi/pytest-bdd
[bravado_core]: https://github.com/Yelp/bravado-core
[PyJWT]: https://pyjwt.readthedocs.io/en/latest
[Requests]: http://docs.python-requests.org/en/master/
[requirements.txt]: https://github.com/dintero/docker-pytest-bdd/blob/master/requirements.txt
