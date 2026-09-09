.PHONY: test test-standard test-docker test-all test-guard test-guard-export test-uripack test-native-export test-native-packages test-repository-plans pack
test:
	python3 -m unittest discover -s tests -v
	python3 -B tools/check_standard.py
	python3 tools/check.py
test-standard:
	python3 -B tools/check_standard.py
test-docker:
	python3 tools/check.py --docker
test-all: test test-docker
test-guard:
	test -n "$(GUARD_REPOSITORY)" -a -n "$(GUARD_REPORT)"
	python3 integration_tests/guard_http.py --repository "$(GUARD_REPOSITORY)" --out "$(GUARD_REPORT)"
test-guard-export:
	test -n "$(GUARD_SOURCE)" -a -n "$(GUARD_REVISION)" -a -n "$(GUARD_OUTPUT)"
	python3 integration_tests/full_guard_export.py --source-repository "$(GUARD_SOURCE)" --source-revision "$(GUARD_REVISION)" --output "$(GUARD_OUTPUT)"
test-uripack:
	test -n "$(URIPROCESS_SOURCE)"
	URIPROCESS_SOURCE="$(URIPROCESS_SOURCE)" python3 -m unittest discover -s tests -p test_uripack.py -v
test-native-export:
	test -n "$(URIPACK_REPOSITORY)" -a -n "$(GUARD_REPOSITORY)" -a -n "$(NATIVE_OUTPUT)"
	python3 tools/verify_native_export.py --uripack-repository "$(URIPACK_REPOSITORY)" --guard-repository "$(GUARD_REPOSITORY)" --output "$(NATIVE_OUTPUT)"
test-native-packages:
	test -n "$(URIPROCESS_CONNECTORS_SOURCE)" -a -n "$(NATIVE_OUTPUT)" -a -n "$(BUILDER_PYTHON)"
	URIPROCESS_CONNECTORS_SOURCE="$(URIPROCESS_CONNECTORS_SOURCE)" python3 -m unittest discover -s tests -p test_native_packages.py -v
	python3 tools/check_native.py --source "$(URIPROCESS_CONNECTORS_SOURCE)" --output "$(NATIVE_OUTPUT)" --builder-python "$(BUILDER_PYTHON)"
pack:
	python3 tools/check.py --pack
test-repository-plans:
	test -n "$(URIPROCESS_SOURCE)" -a -n "$(URIPROCESS_CONNECTORS_SOURCE)"
	URIPROCESS_SOURCE="$(URIPROCESS_SOURCE)" URIPROCESS_CONNECTORS_SOURCE="$(URIPROCESS_CONNECTORS_SOURCE)" python3 -m unittest discover -s tests -p 'test_repository_*.py' -v
