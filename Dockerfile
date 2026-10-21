# Use an official Python runtime as a parent image
FROM python:3.11-slim

# Install wkhtmltopdf for optional PDF generation
RUN apt-get update && apt-get install -y --no-install-recommends \
    wkhtmltopdf \
    && rm -rf /var/lib/apt/lists/*

# Set the working directory in the container
WORKDIR /app

# Copy requirements and install them
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the current directory contents into the container
COPY . .

# Run the pipeline when the container launches
ENTRYPOINT ["python", "vuln2risk.py"]
