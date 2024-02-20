FROM python:3.10-slim

WORKDIR /app

COPY main.py auth.py requirements.txt /app/

RUN apt-get update -y && \
    apt-get upgrade -y && \
    pip install -U pip setuptools && \
    pip install -r requirements.txt

ENTRYPOINT ["uvicorn"]

CMD ["--host", "0.0.0.0", "main:app"]

EXPOSE 8000
