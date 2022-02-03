FROM wordpress:5.6-php7.4-apache

COPY ./my-entrypoint.sh /usr/local/bin/my-entrypoint.sh

RUN apt update &&\
    apt install -y cron &&\
    touch /var/log/cron.log &&\
    chmod +x /usr/local/bin/my-entrypoint.sh

ENTRYPOINT [ "my-entrypoint.sh" ]
CMD [ "apache2-foreground" ]