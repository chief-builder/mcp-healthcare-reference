FROM python:3.14.7-slim

RUN pip install --no-cache-dir "fastapi==0.142.*" "uvicorn==0.54.*" "pyjwt==2.15.*" "cryptography==50.0.*" "python-multipart==0.0.*"

COPY main.py /app/main.py
WORKDIR /app

EXPOSE 7000
USER 65534
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "7000"]
