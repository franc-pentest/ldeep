EXEC = ldeep.bin

SRC = $(wildcard ./ldeep/*.py)

all: $(EXEC)

$(EXEC): $(SRC)
	pdm build --no-sdist
	pex -r requirements.txt --disable-cache -f dist/ -o $@ -e ldeep.__main__ ldeep

release: $(SRC)
	git tag $(shell cat VERSION)
	git push origin $(shell cat VERSION)
	pdm build --no-wheel
	twine upload dist/*

release-test: $(SRC)
	pdm build --no-wheel
	twine upload --repository testpypi dist/*

clean:
	@rm -rf build/ dist/

mrproper: clean
	@find . -name *.pyc -exec rm '{}' \;
	@rm -rf *.egg-info

export:
	pdm export -f requirements --without-hashes --prod > requirements.txt
	pdm export -f requirements --without-hashes --dev > requirements-dev.txt
	pdm lock

.PHONY: clean mrproper
