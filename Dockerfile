# Use Python 3.14 on Alpine Linux
FROM python:3.14-alpine

# Build arguments for authentication configuration
ARG AUTH_METHOD=no_auth
ARG USERNAME
ARG PASSWORD
ARG PORT=1080
ARG BIND_ADDRESS=0.0.0.0

# Set environment variables from build args
ENV AUTH_METHOD=$AUTH_METHOD
ENV USERNAME=$USERNAME
ENV PASSWORD=$PASSWORD
ENV PORT=$PORT
ENV BIND_ADDRESS=$BIND_ADDRESS

# Set working directory
WORKDIR /app

# Copy the socksify5 package
COPY socksify5/ ./socksify5/

# Copy the entrypoint script
COPY run_server.py .

# Expose the port
EXPOSE $PORT

# Run the server
CMD ["python", "run_server.py"]