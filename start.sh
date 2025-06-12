#!/bin/bash
echo "Waiting for ZAP on port $ZAP_PORT..."
while ! curl -s http://zap:${ZAP_PORT} > /dev/null; do
    sleep 1
done

echo "Waiting for Ollama on port $OLLAMA_PORT..."
while ! curl -s http://ollama:${OLLAMA_PORT}/api/tags > /dev/null; do
    sleep 1
done

echo "Pulling model..."
curl -X POST http://ollama:${OLLAMA_PORT}/api/pull -d '{"name":"phi4-mini:latest"}'

echo "Starting FastAPI server..."
uvicorn api:app --host 0.0.0.0 --port 8000 --reload
