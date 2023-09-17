TAG ?= dintero/docker-pytest-bdd
PYTEST_ADDOPTS ?=-vv --gherkin-terminal-reporter --cucumberjson-expanded
COMPOSE_DEFAULT_FLAGS=-f example/docker-compose.yml
DOCKER_BUILDKIT ?= 1
PLATFORMS ?= linux/amd64,linux/arm64

.EXPORT_ALL_VARIABLES:
PYTEST_ADDOPTS := $(PYTEST_ADDOPTS)

export DOCKER_BUILDKIT
build:
	@docker buildx build --platform $(PLATFORMS) --tag $(TAG) .

.PHONY: down
down:
	docker-compose $(COMPOSE_DEFAULT_FLAGS) $@

test: down
	docker-compose $(COMPOSE_DEFAULT_FLAGS) build
	PYTEST_ADDOPTS="$(PYTEST_ADDOPTS)" docker-compose $(COMPOSE_DEFAULT_FLAGS) run --service-ports --rm end-to-end-tests

publish: build
	@docker buildx build --platform $(PLATFORMS) --tag $(TAG) --push .

install: build test
