# Portable characterization tests.  No iOS SDK, Theos or production build is
# required; the Python runner uses only the standard library.

PYTHON ?= python3
MAKEFLAGS += --no-print-directory

test: host
	@PYTHONDONTWRITEBYTECODE=1 $(PYTHON) characterize.py

host: host-rebind host-path-policy host-environment-policy

host-rebind:
	@RHI_HOST_BIN="$$(mktemp -t rhi-rebind-metadata.XXXXXX)"; \
	trap 'rm -f "$$RHI_HOST_BIN"' EXIT; \
	xcrun --sdk macosx clang -std=c11 -Werror -I../src rhi_rebind_metadata_host.c -o "$$RHI_HOST_BIN"; \
	"$$RHI_HOST_BIN"

host-path-policy:
	@RHI_HOST_BIN="$$(mktemp -t rhi-path-policy.XXXXXX)"; \
	trap 'rm -f "$$RHI_HOST_BIN"' EXIT; \
	xcrun --sdk macosx clang -std=c11 -Wall -Wextra -Werror -I../src \
		hider_path_policy_host.c ../src/hider_path_policy.c -o "$$RHI_HOST_BIN"; \
	"$$RHI_HOST_BIN"

host-environment-policy:
	@RHI_HOST_BIN="$$(mktemp -t rhi-environment-policy.XXXXXX)"; \
	trap 'rm -f "$$RHI_HOST_BIN"' EXIT; \
	xcrun --sdk macosx clang -std=c11 -Wall -Wextra -Werror \
		-fsanitize=address,undefined -fno-omit-frame-pointer -I../src \
		hider_environment_policy_host.c ../src/hider_environment_policy.c -o "$$RHI_HOST_BIN"; \
	"$$RHI_HOST_BIN"

json:
	@PYTHONDONTWRITEBYTECODE=1 $(PYTHON) characterize.py --json

artifact:
	@PYTHONDONTWRITEBYTECODE=1 $(PYTHON) characterize.py --artifact ../systemhook.dylib

.PHONY: test host host-rebind host-path-policy host-environment-policy json artifact
