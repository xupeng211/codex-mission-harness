.PHONY: format lint test verify deepseek-review

format:
	python3 -m compileall -q src scripts

lint:
	python3 -m compileall -q src tests

test:
	PYTHONPATH=src python3 -m unittest discover -s tests -v

verify: format lint test

deepseek-review: ## Usage: make deepseek-review BASE=<sha> HEAD=<sha> EVIDENCE=<dir> TOKEN_FILE=<path>
	@test -n "$(BASE)" -a -n "$(HEAD)" -a -n "$(EVIDENCE)" -a -n "$(TOKEN_FILE)" || (echo "BASE HEAD EVIDENCE TOKEN_FILE are required"; exit 2)
	@python3 scripts/deepseek_review.py run --base "$(BASE)" --head "$(HEAD)" --evidence "$(EVIDENCE)" --token-file "$(TOKEN_FILE)"

.PHONY: anthropic-review
anthropic-review: ## Usage: make anthropic-review BASE=<sha> HEAD=<sha> EVIDENCE=<dir> RECEIPT_KEY_FILE=<path>
	@test -n "$(BASE)" -a -n "$(HEAD)" -a -n "$(EVIDENCE)" -a -n "$(RECEIPT_KEY_FILE)" || (echo "BASE HEAD EVIDENCE RECEIPT_KEY_FILE are required"; exit 2)
	@python3 scripts/anthropic_review.py run --base "$(BASE)" --head "$(HEAD)" --evidence "$(EVIDENCE)" --receipt-key-file "$(RECEIPT_KEY_FILE)"
