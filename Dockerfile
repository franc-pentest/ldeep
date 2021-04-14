# Build command: docker build -t ldeep .
# Execute with: docker run --rm ldeep $args

FROM python:3.8-slim-buster
WORKDIR /ldeep
COPY . .
RUN pip install -r requirements.txt
RUN [ "python", "setup.py", "install" ]
ENTRYPOINT [ "ldeep" ]
