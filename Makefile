SHELL := /bin/sh
REGION ?= africa-south1
TAG ?= dev
KUSTOMIZE_OVERLAY ?= demo

.DEFAULT_GOAL := help
.PHONY: help dev down test build load-latency load-throughput bootstrap deploy evaluate-next terraform-check kustomize-check

help:
	@printf '%s\n' 'make dev | down | test | build | load-latency | load-throughput | bootstrap PROJECT_ID=... | deploy PROJECT_ID=... DOMAIN=... | evaluate-next'

dev:
	docker compose up --build

down:
	docker compose down

test:
	cd backend && uv run --extra test pytest
	cd fetcher && uv run --extra dev pytest
	cd frontend && corepack prepare pnpm@10.15.1 --activate && pnpm test

build:
	docker build -f Dockerfile.app -t phishguard-app:$(TAG) .
	docker build -f Dockerfile.fetcher -t phishguard-fetcher:$(TAG) .

load-latency:
	K6_PROFILE=latency k6 run load/k6/local-scans.js

load-throughput:
	K6_PROFILE=throughput k6 run load/k6/local-scans.js

bootstrap:
	@test -n "$(PROJECT_ID)" || (echo 'PROJECT_ID is required' >&2; exit 2)
	PROJECT_ID=$(PROJECT_ID) REGION=$(REGION) ./deploy/scripts/bootstrap.sh

deploy:
	@test -n "$(PROJECT_ID)" -a -n "$(DOMAIN)" || (echo 'PROJECT_ID and DOMAIN are required' >&2; exit 2)
	PROJECT_ID=$(PROJECT_ID) REGION=$(REGION) DOMAIN=$(DOMAIN) DNS_ZONE=$(DNS_ZONE) TAG=$(TAG) KUSTOMIZE_OVERLAY=$(KUSTOMIZE_OVERLAY) ./deploy/scripts/deploy.sh

evaluate-next:
	kubectl -n phishguard-demo create job --from=cronjob/evaluate evaluate-$$(date -u +%Y%m%d%H%M%S)

terraform-check:
	terraform -chdir=infra/terraform fmt -check -recursive
	terraform -chdir=infra/terraform validate

kustomize-check:
	kubectl kustomize deploy/k8s/overlays/demo >/dev/null
