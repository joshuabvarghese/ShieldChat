FROM mysql:8.0.22
#set mysql environment variables for credentials
ENV MYSQL_ROOT_PASSWORD=root
ENV MYSQL_PASSWORD=root
#copy schema file into container dir
COPY mysql_schema.sql /docker-entrypoint-initdb.d
 
RUN chown -R mysql:mysql /docker-entrypoint-initdb.d/