FROM php:8.2-apache
COPY index.php /var/www/html/index.php
RUN chown -R root:root /var/www/html
RUN chmod 655 /var/www/html
COPY flag.txt /flag.txt