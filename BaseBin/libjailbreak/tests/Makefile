# Portable trustcache geometry characterization tests. No iOS SDK or kernel
# primitives are required; the runner uses only the host Python standard
# library and static assertions against the production source.

PYTHON ?= python3
MAKEFLAGS += --no-print-directory

test:
	@echo "== trustcache characterization =="
	@PYTHONDONTWRITEBYTECODE=1 $(PYTHON) characterize.py
	@echo "== libjailbreak ABI contract =="
	@PYTHONDONTWRITEBYTECODE=1 $(PYTHON) abi_contract.py
	@echo "== TXM/trust/signature contract =="
	@PYTHONDONTWRITEBYTECODE=1 $(PYTHON) txm_trust_contract.py
	@echo "== trustcache transaction model =="
	@PYTHONDONTWRITEBYTECODE=1 $(PYTHON) trustcache_transaction_model.py
	@echo "== filesystem trustcache status contract =="
	@PYTHONDONTWRITEBYTECODE=1 $(PYTHON) trustcache_fs_status_contract.py

json:
	@PYTHONDONTWRITEBYTECODE=1 $(PYTHON) characterize.py --json

.PHONY: test json
