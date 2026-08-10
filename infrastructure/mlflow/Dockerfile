FROM ghcr.io/mlflow/mlflow:v2.20.0@sha256:eed75937d3c28970eac3cbeedfadab4926e6c19f083283b099bb6954473d7ff2
COPY infrastructure/mlflow/requirements.lock /tmp/requirements.lock
RUN python -m pip install --no-cache-dir --require-hashes -r /tmp/requirements.lock \
    && python -c "import psycopg2; assert psycopg2.__version__.startswith('2.9.10')" \
    && rm /tmp/requirements.lock
