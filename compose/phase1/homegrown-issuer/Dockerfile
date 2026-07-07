FROM python:3.12-slim

RUN pip install --no-cache-dir "fastapi==0.115.*" "uvicorn==0.32.*" "pyjwt==2.10.*" "cryptography==44.0.*" "python-multipart==0.0.*"

COPY main.py /app/main.py
WORKDIR /app

EXPOSE 7000
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "7000"]
