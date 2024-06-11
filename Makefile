SRC = $(wildcard ./ldeep/*.py)

all: build

build:
	pdm build -d sdist

pypi: $(SRC)
	twine upload sdist/*

pypi-test: $(SRC)
	twine upload --repository testpypi sdist/*

clean:
	@rm -rf build/ sdist/

mrproper: clean
	@find . -name *.pyc -exec rm '{}' \;
	@rm -rf *.egg-info

export:
	pdm lock
	pdm export -f requirements --without-hashes --prod > requirements.txt
	pdm export -f requirements --without-hashes --dev > requirements-dev.txt

.PHONY: clean mrproper build
