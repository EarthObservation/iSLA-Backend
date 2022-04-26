# pull official base image
FROM python:3.6-slim-buster

# set work directory
WORKDIR /usr/src/isla

# set environment variables
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

# install system dependencies
RUN apt-get update && apt-get install -y netcat

# install dependencies
RUN pip install --upgrade pip
COPY ./requirements.txt /usr/src/isla/requirements.txt
RUN pip install -r requirements.txt

# copy project
COPY . /usr/src/isla/

# run entrypoint.sh
ENTRYPOINT ["/usr/src/isla/entrypoint.sh"]