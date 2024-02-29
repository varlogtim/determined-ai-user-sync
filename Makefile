
.PHONY: fmt
fmt:
	black .
	isort .

.PHONY: check
check:
	isort . --check-only
	# black . --check
	python -m flake8
	mypy .
