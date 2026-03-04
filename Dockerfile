FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy entire project (including app module for imports)
COPY . .

# Make CLI executable
RUN chmod +x cli.py solsift

# Set API_BASE_URL - user can override with -e API_BASE_URL=...
ENV API_BASE_URL="http://api:8000"

# Default command
ENTRYPOINT ["python3.11", "cli.py"]
CMD ["--help"]
