# Build command: docker build -t ldeep .
# Execute with: docker run --rm ldeep $args

FROM python:3.12-slim
WORKDIR /ldeep
RUN apt-get update && apt-get install -y libkrb5-dev gcc python3-dev
COPY . .
RUN PDM_BUILD_SCM_VERSION=$(cat VERSION) pip install .
ENTRYPOINT [ "ldeep" ]
