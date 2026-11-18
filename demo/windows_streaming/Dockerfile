FROM python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b
WORKDIR /app
COPY src/raneval/__init__.py src/raneval/windows_stream.py src/raneval/windows_events.py src/raneval/windows_native.py src/raneval/windows_native_v1.py /app/raneval/
COPY demo/windows_streaming/server.py /app/server.py
COPY demo/windows_streaming/static /app/static
COPY demo/windows_streaming/model.json /app/model.json
COPY demo/windows_streaming/native-model.json /app/native-model.json
USER 65534:65534
EXPOSE 8767
CMD ["python", "server.py", "--host", "0.0.0.0"]
