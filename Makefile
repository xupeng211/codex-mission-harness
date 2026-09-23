.PHONY: format lint test verify

format:
	python3 -m compileall -q src

lint:
	python3 -m compileall -q src tests

test:
	PYTHONPATH=src python3 -m unittest discover -s tests -v

verify: format lint test
