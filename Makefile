# Developer shortcuts. Run `make help`.
SHELL := /bin/bash
TF ?= terraform
ENV ?= nonprod
WS ?= pki-core

TF_DIRS := $(shell find modules environments bootstrap examples -name '*.tf' -not -path '*/.terraform/*' -exec dirname {} \; | sort -u)
TEST_DIRS := $(shell find modules environments -name '*.tftest.hcl' -exec dirname {} \; | xargs -n1 dirname | sort -u)

.PHONY: help fmt fmt-check validate test-tf test-python lint security check lambda-build plan inventory sentinel-test clean

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

fmt: ## Format all Terraform files
	$(TF) fmt -recursive

fmt-check: ## Check Terraform formatting (CI)
	$(TF) fmt -check -recursive -diff

lambda-build: ## Build Lambda packages into lambda/dist (needed before validate/plan)
	./lambda/build.sh

validate: lambda-build ## terraform init -backend=false + validate in every directory
	@set -e; for d in $(TF_DIRS); do echo "==> $$d"; $(TF) -chdir=$$d init -backend=false -input=false >/dev/null; $(TF) -chdir=$$d validate; done

test-tf: ## Terraform module unit tests (mocked providers, no AWS needed)
	@set -e; for d in $(TEST_DIRS); do echo "==> $$d"; $(TF) -chdir=$$d init -backend=false -input=false >/dev/null; $(TF) -chdir=$$d test; done

test-python: ## Python unit tests (Lambdas, scripts, CI helpers)
	python3 -m pytest -q

lint: ## tflint
	tflint --init --config $(CURDIR)/.tflint.hcl && tflint --recursive --config $(CURDIR)/.tflint.hcl

security: ## Checkov scan
	checkov -d . --config-file .checkov.yaml

sentinel-test: ## Sentinel policy tests (needs the sentinel CLI)
	cd policies/sentinel && sentinel test

check: fmt-check validate test-tf test-python ## Everything CI runs that does not need HCP Terraform

plan: lambda-build ## Remote speculative plan, e.g. make plan ENV=nonprod WS=pki-core (needs `terraform login`)
	$(TF) -chdir=environments/$(ENV)/$(WS) init -input=false
	$(TF) -chdir=environments/$(ENV)/$(WS) plan

inventory: ## Certificate / CA inventory of the current AWS profile
	python3 scripts/cert_inventory.py --regions ca-central-1 us-east-1

clean: ## Remove local build artefacts
	rm -rf lambda/dist **/.build
	find . -name .terraform -type d -prune -exec rm -rf {} +
