# Build command: docker build -t ldeep .
# Execute with: docker run --rm ldeep $args

FROM python:3.12-slim
WORKDIR /ldeep
RUN apt-get update && apt-get install -y --no-install-recommends \
    git libkrb5-dev gcc python3-dev \
    && rm -rf /var/lib/apt/lists/*
COPY . .
RUN pip install .
ENTRYPOINT [ "ldeep" ]
