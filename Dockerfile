# Use an official Python runtime as a parent image
FROM python:3.9-slim

# Set the working directory to /app
WORKDIR /app

# Copy the current directory contents into the container at /app
COPY requirements.txt .

# Install any dependencies specified in requirements.txt
RUN pip install -r requirements.txt
COPY . .

# Make port 80 available to the world outside this container
EXPOSE 8000

# Define environment variable

# Run app.py when the container launches
CMD ["python", "app/Backend.py"]