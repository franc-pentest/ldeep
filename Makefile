EXEC = ldeep.bin

SRC = $(wildcard ./ldeep/*.py)

all: $(EXEC)

$(EXEC): $(SRC)
	python3 setup.py bdist_wheel
	pex -r requirements.txt --disable-cache -f dist/ -o $@ -e ldeep.__main__ ldeep

release: $(SRC)
	python3 setup.py sdist

clean:
	@rm -rf build/ dist/

mrproper: clean
	@find . -name *.pyc -exec rm '{}' \;
	@rm -rf *.egg-info

.PHONY: clean mrproper
