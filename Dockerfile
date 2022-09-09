FROM ubuntu:22.04

ENV PYTHONFAULTHANDLER=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONHASHSEED=random \
    PIP_NO_CACHE_DIR=off \
    PIP_DISABLE_PIP_VERSION_CHECK=on \
    PIP_DEFAULT_TIMEOUT=100 \
    POETRY_VERSION=1.1.13

RUN apt-get update && apt-get upgrade -y && apt-get install -y ssh vim byobu python3-pip

# System deps:
RUN pip install "poetry==$POETRY_VERSION"

WORKDIR /code
COPY  ./poetry.lock ./pyproject.toml /code/

RUN poetry config virtualenvs.create false \
    && poetry install --no-interaction --no-ansi
