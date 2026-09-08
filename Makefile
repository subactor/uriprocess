.PHONY: test test-docker test-all pack
test:
	python3 -m unittest discover -s tests -v
	python3 tools/check.py
test-docker:
	python3 tools/check.py --docker
test-all: test test-docker
pack:
	python3 tools/check.py --pack
