# Standalone container image for verify.py -- run a verification
# without installing Python/cryptography locally at all.
#
# Usage:
#   docker build -t actaseal-verify .
#   docker run --rm -v $(pwd)/packet:/packet actaseal-verify /packet

FROM python:3.12-slim

RUN pip install --no-cache-dir cryptography

WORKDIR /app
COPY verify.py .

ENTRYPOINT ["python", "/app/verify.py"]
