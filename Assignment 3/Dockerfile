# syntax=docker/dockerfile:1
FROM python:3.8

WORKDIR /app

# copy all the files to the container
COPY . .

# install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# define the port number the container should expose
EXPOSE 5001

# run the command
CMD ["python", "app.py"]