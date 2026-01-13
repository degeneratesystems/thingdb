FROM python:3.10-slim
WORKDIR /app
COPY . /app
RUN pip install --no-cache-dir -r requirements.txt
EXPOSE 5000 5443
ENTRYPOINT ["python3", "examples/peer_server.py"]
