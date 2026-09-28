PYTHON ?= python3

setup:
	$(PYTHON) -m pip install --upgrade pip
	$(PYTHON) -m pip install -e .

synth-data:
	$(PYTHON) scripts/synth_data.py

train:
	$(PYTHON) scripts/train.py

demo:
	$(PYTHON) -m uvicorn ipsecguard.api.main:app --host 0.0.0.0 --port 8000

test:
	$(PYTHON) -m pytest

lint:
	$(PYTHON) -m ruff check .
