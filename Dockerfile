# Use an official Node.js image as the base
FROM node:20-bullseye-slim

# Install Python and pip
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    python3-venv \
    && rm -rf /var/lib/apt/lists/*

# Set up the working directory
WORKDIR /app

# Copy both scanner and dashboard directories
COPY scanner /app/scanner
COPY dashboard /app/dashboard

# Set up Python environment for the scanner
WORKDIR /app/scanner
RUN python3 -m venv venv
ENV PATH="/app/scanner/venv/bin:$PATH"
RUN pip install -r requirements.txt

# Set up and build the Next.js dashboard
WORKDIR /app/dashboard
RUN npm install
RUN npm run build

# Expose the port Next.js runs on
EXPOSE 3000

# Start the Next.js server
CMD ["npm", "start"]
