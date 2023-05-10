# syntax=docker/dockerfile:1
FROM python:3.8

WORKDIR /app

# copy all the files to the container
COPY . .

# install dependencies
RUN pip install --no-cache-dir -r requirements.txt

RUN pip install psycopg2-binary

# define the port number the container should expose
EXPOSE 5001

# run the command
CMD ["python", "app_v1.py"]