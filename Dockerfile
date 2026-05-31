FROM python:3.12-slim

WORKDIR /app

# Install build tools (needed for some native dependencies like cryptography)
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy project files
COPY pyproject.toml ./
COPY src/ ./src/

# Install the package with all dependencies
RUN pip install --no-cache-dir -e "."

# Railway sets PORT automatically; default to 8080 for local dev
ENV PORT=8080

EXPOSE $PORT

# Start the HTTP server. Uses TP_AUTH_COOKIE and MCP_API_KEY from env.
CMD ["sh", "-c", "tp-mcp serve-http --port $PORT"]
