FROM python:3
#copy files from dockerfiles dir into container
COPY . /app

WORKDIR /app
#install all the python modules to the container
RUN pip install --no-cache-dir -r requirements.txt
#execute python script app.py in container
CMD ["python","-u","./app.py"]