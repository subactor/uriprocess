.PHONY: test test-docker test-all test-guard test-guard-export pack
test:
	python3 -m unittest discover -s tests -v
	python3 tools/check.py
test-docker:
	python3 tools/check.py --docker
test-all: test test-docker
test-guard:
	test -n "$(GUARD_REPOSITORY)" -a -n "$(GUARD_REPORT)"
	python3 integration_tests/guard_http.py --repository "$(GUARD_REPOSITORY)" --out "$(GUARD_REPORT)"
test-guard-export:
	test -n "$(GUARD_SOURCE)" -a -n "$(GUARD_REVISION)" -a -n "$(GUARD_OUTPUT)"
	python3 integration_tests/full_guard_export.py --source-repository "$(GUARD_SOURCE)" --source-revision "$(GUARD_REVISION)" --output "$(GUARD_OUTPUT)"
pack:
	python3 tools/check.py --pack
