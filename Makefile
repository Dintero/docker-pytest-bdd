TAG ?= dintero/docker-pytest-bdd
PYTEST_ADDOPTS ?=-vv --gherkin-terminal-reporter --cucumberjson-expanded
DOCKER_BUILDKIT ?= 1

export DOCKER_BUILDKIT
build:
	@docker build --tag $(TAG) .

test:
	@docker run \
	--rm \
	-e PYTEST_ADDOPTS="$(PYTEST_ADDOPTS)" \
	-v $(CURDIR)/example:/example \
	-w /example $(TAG) \
	pytest

publish: build
	docker push $(TAG)

install: build test
