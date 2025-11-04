# Use Apify's Python base image
FROM apify/actor-python:3.11

# Install Java (for Ghidra) and other system dependencies
RUN apt-get update && apt-get install -y \
    openjdk-17-jdk \
    wget \
    unzip \
    binutils \
    file \
    && rm -rf /var/lib/apt/lists/*

# Download and extract Ghidra (version 11.0.1 - latest stable)
RUN wget -q -O /tmp/ghidra.zip https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.0.1_build/ghidra_11.0.1_PUBLIC_20240130.zip \
    && unzip -q /tmp/ghidra.zip -d /opt \
    && rm /tmp/ghidra.zip \
    && mv /opt/ghidra_* /opt/ghidra

# Set GHIDRA_HOME environment variable
ENV GHIDRA_HOME=/opt/ghidra
ENV PATH="${GHIDRA_HOME}/support:${PATH}"

# Set working directory
WORKDIR /app

# Copy requirements first for better caching
COPY requirements.txt ./

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy Ghidra scripts
COPY ghidra_scripts /app/ghidra_scripts

# Copy actor source code
COPY src ./src
COPY apify.json input_schema.json ./

# Create necessary directories
RUN mkdir -p /tmp/ghidra_projects /tmp/analysis_output

# Set the entrypoint to run our actor's main script
ENTRYPOINT ["python", "-m", "src.main"]
