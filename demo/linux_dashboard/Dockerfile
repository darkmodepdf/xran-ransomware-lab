FROM python:3.12.16-slim-bookworm@sha256:935c3c5b12357a7e10caa9c1e6ca5692344d97cf229832ef584be2cec9fc03df

RUN python -m pip install --no-cache-dir 'onnxruntime==1.23.2' 'numpy==2.3.5'

WORKDIR /app
COPY demo/runner.py demo/model_adapter.py demo/linux_dashboard/server.py ./
COPY demo/linux_dashboard/static/ ./static/
ENV TMPDIR=/tmp HOME=/tmp PYTHONDONTWRITEBYTECODE=1 OMP_NUM_THREADS=1 OPENBLAS_NUM_THREADS=1
USER 10001:10001
EXPOSE 8080

ENTRYPOINT ["python", "-B", "-u", "/app/server.py", "--host", "0.0.0.0"]
