FROM python:3.12-slim
RUN pip install --no-cache-dir 'requests==2.32.*'
WORKDIR /app
COPY agent.py .
USER 65534
CMD ["python", "-u", "agent.py"]
