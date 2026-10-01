FROM python:3.14.7-slim
RUN pip install --no-cache-dir 'requests==2.34.*'
WORKDIR /app
COPY agent.py .
USER 65534
CMD ["python", "-u", "agent.py"]
