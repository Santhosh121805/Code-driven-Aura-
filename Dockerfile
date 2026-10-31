FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
# Listen on all interfaces inside the container so the host can reach the ports.
ENV BIND_HOST=0.0.0.0 PYTHONUNBUFFERED=1
EXPOSE 8000 9001 9002 9003 9004
CMD ["python", "run_all.py"]
