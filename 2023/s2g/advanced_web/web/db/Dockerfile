FROM mariadb
ENV MARIADB_DATABASE=nonsense \
    MARIADB_ROOT_PASSWORD=a00e2a2b98c6c8b6ef741aeb0715d2b4

ADD init.sql /docker-entrypoint-initdb.d
EXPOSE 3306
