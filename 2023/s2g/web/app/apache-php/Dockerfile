FROM php:7.4-apache

RUN a2enmod rewrite proxy proxy_http

COPY apache.conf /etc/apache2/sites-available/000-default.conf

WORKDIR /var/www/html/

COPY index.php /var/www/html/

CMD ["apache2-foreground"]