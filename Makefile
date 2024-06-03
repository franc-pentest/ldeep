EXEC = ldeep.bin

SRC = $(wildcard ./ldeep/*.py)

all: $(EXEC)

$(EXEC): $(SRC)
	pdm build --no-sdist
	pex -r requirements.txt --disable-cache -f dist/ -o $@ -e ldeep.__main__ ldeep

pypi: $(SRC)
	pdm build -d sdist --no-wheel
	twine upload sdist/*

pypi-test: $(SRC)
	pdm build -d sdist --no-wheel
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

.PHONY: clean mrproper
