.PHONY: test test-docker test-all test-guard pack
test:
	python3 -m unittest discover -s tests -v
	python3 tools/check.py
test-docker:
	python3 tools/check.py --docker
test-all: test test-docker
test-guard:
	test -n "$(GUARD_REPOSITORY)" -a -n "$(GUARD_REPORT)"
	python3 integration_tests/guard_http.py --repository "$(GUARD_REPOSITORY)" --out "$(GUARD_REPORT)"
pack:
	python3 tools/check.py --pack
