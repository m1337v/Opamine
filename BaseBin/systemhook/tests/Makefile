# Portable characterization tests.  No iOS SDK, Theos or production build is
# required; the Python runner uses only the standard library.

PYTHON ?= python3
MAKEFLAGS += --no-print-directory

test:
	@PYTHONDONTWRITEBYTECODE=1 $(PYTHON) characterize.py

json:
	@PYTHONDONTWRITEBYTECODE=1 $(PYTHON) characterize.py --json

artifact:
	@PYTHONDONTWRITEBYTECODE=1 $(PYTHON) characterize.py --artifact ../systemhook.dylib

.PHONY: test json artifact
