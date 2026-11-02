.PHONY: format lint contract-check test verify deepseek-review

format:
	python3 -m compileall -q src scripts

lint:
	python3 -m compileall -q src tests

contract-check:
	python3 -B tests/footballprediction_contract.py

test: contract-check
	PYTHONPATH=src python3 -m unittest discover -s tests -v

verify: contract-check format lint test

deepseek-review: ## Usage: make deepseek-review BASE=<sha> HEAD=<sha> EVIDENCE=<dir> TOKEN_FILE=<path>
	@test -n "$(BASE)" -a -n "$(HEAD)" -a -n "$(EVIDENCE)" -a -n "$(TOKEN_FILE)" || (echo "BASE HEAD EVIDENCE TOKEN_FILE are required"; exit 2)
	@python3 scripts/deepseek_review.py run --base "$(BASE)" --head "$(HEAD)" --evidence "$(EVIDENCE)" --token-file "$(TOKEN_FILE)"
