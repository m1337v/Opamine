# Portable characterization tests.  No iOS SDK, Theos or production build is
# required; the Python runner uses only the standard library.

PYTHON ?= python3
MAKEFLAGS += --no-print-directory

test: host
	@PYTHONDONTWRITEBYTECODE=1 $(PYTHON) characterize.py

host:
	@RHI_HOST_BIN="$$(mktemp -t rhi-rebind-metadata.XXXXXX)"; \
	trap 'rm -f "$$RHI_HOST_BIN"' EXIT; \
	xcrun --sdk macosx clang -std=c11 -Werror -I../src rhi_rebind_metadata_host.c -o "$$RHI_HOST_BIN"; \
	"$$RHI_HOST_BIN"

json:
	@PYTHONDONTWRITEBYTECODE=1 $(PYTHON) characterize.py --json

artifact:
	@PYTHONDONTWRITEBYTECODE=1 $(PYTHON) characterize.py --artifact ../systemhook.dylib

.PHONY: test host json artifact
