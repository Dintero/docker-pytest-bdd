
TAG ?= dintero/docker-pytest-bdd
PYTEST_ADDOPTS ?=-vv --gherkin-terminal-reporter --cucumberjson-expanded

build:
	@docker build -t $(TAG) .

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
