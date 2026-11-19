PY ?= python3

.PHONY: demo test verify audit clean rules

demo:
	./demo.sh

test:
	$(PY) -m unittest discover -s tests -v

verify:
	$(PY) tools/acceptance.py

audit:
	$(PY) audit.py audit fixtures/estate_12.json --claims fixtures/claims.json --out out/estate_12

rules:
	$(PY) audit.py rules

clean:
	rm -rf out
