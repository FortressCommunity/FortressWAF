# Build recipe for the demo target behind demo.tkjt3yapera.my.id.
#
# Source: github.com/daffainfo/vulnerable-web @ 79d499f (2022-12-30)
# The labs in that app are the point: the WAF is supposed to block them, and
# the audit log is supposed to fill up. It is deliberately vulnerable, so it
# runs on its own isolated network (see docker-compose.yml, demo-net).
#
# Upstream ships "FROM ubuntu:latest", which is now 26.04 where the php8.1
# packages no longer exist, so the build fails. Only the base tag is changed
# below; every other step matches upstream.
#
# Build from the clone, not from this directory:
#   docker build -f deploy/demo-app/Dockerfile /path/to/vulnerable-web \
#     -t fortresswaf/vulnerable-web:latest \
#     --build-arg email=demo@example.com --build-arg password_email=demo-password

FROM ubuntu:22.04

ARG DEBIAN_FRONTEND=noninteractive

# Consumed by the Host Header Injection lab, which mails these to whatever
# host the attacker supplies. Lab values, not real credentials.
ARG email
ENV env_email $email
ARG password_email
ENV env_password $password_email

RUN apt-get update && apt-get install -y \
  nginx \
  php8.1-mysql \
  php8.1-fpm \
  php8.1 \
  mysql-server

COPY app /var/www/html

RUN chown -R www-data:www-data /var/www/html/
RUN chmod -R 777 /var/www/html/

RUN service mysql stop && usermod -d /var/lib/mysql/ mysql

COPY conf/default /etc/nginx/sites-enabled/default
COPY conf/database.sql .

RUN service mysql start && \
  mysql -u root -e "CREATE DATABASE vulnweb;" && \
  mysql -u root -e "CREATE USER 'vulnerableweb'@'%' IDENTIFIED BY 'vulnerableweb';" && \
  mysql -u root -e "GRANT ALL PRIVILEGES ON vulnweb.* TO 'vulnerableweb'@'%';" && \
  mysql -u root -e "FLUSH PRIVILEGES;" && \
  mysql -u vulnerableweb -pvulnerableweb vulnweb < database.sql

RUN rm database.sql

EXPOSE 80 3306

COPY startup.sh .
RUN chmod 700 startup.sh
CMD ["/bin/bash","-c","./startup.sh"]
