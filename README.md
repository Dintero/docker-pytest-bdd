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
 - python-jose
 - pytest-bdd
 - pytest-parallel
 - pytest
 - [Requests]: HTTP for Humans

See the [requirements.txt] for complete list of libraries installed by the [Dockerfile].

## Dintero E2E helpers

The image also ships a small `dintero_e2e` package (source: `helpers/`)
for cross-repo E2E utilities.

### `dintero_e2e.har_capture` — HAR export of E2E-driven HTTP requests

Feed the resulting HAR file to ZAP (via `/JSON/exim/action/importHar/`),
Burp, or curl-replay tooling to run security scans post-hoc without
needing an inline proxy during the E2E run. Also gives you a portable,
inspectable artifact you can attach to compliance audits.

```python
# conftest.py
import pytest
from dintero_e2e import har_capture

@pytest.fixture(scope="session", autouse=True)
def har_output_dump():
    yield
    if har_capture.enabled():
        har_capture.dump()
```

```python
# test_features.py (or wherever HTTP calls happen)
from datetime import datetime
from dintero_e2e import har_capture

def _do_request(request_ctx):
    started = datetime.utcnow()
    response = requests.request(...)
    har_capture.capture(started, response)
    return response
```

Enable by setting `HAR_OUT=/path/to/output.har` before pytest starts.
When unset, `capture()` and `dump()` are no-ops.

[Dockerfile]: https://github.com/dintero/docker-pytest-bdd/blob/master/Dockerfile
[pytest-bdd]: https://pypi.python.org/pypi/pytest-bdd
[bravado_core]: https://github.com/Yelp/bravado-core
[PyJWT]: https://pyjwt.readthedocs.io/en/latest
[Requests]: http://docs.python-requests.org/en/master/
[requirements.txt]: https://github.com/dintero/docker-pytest-bdd/blob/master/requirements.txt
