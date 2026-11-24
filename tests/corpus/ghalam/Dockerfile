FROM php:8.3-apache

# PHP connects to a separate PostgreSQL container through PDO.
RUN apt-get update \
    && apt-get install -y --no-install-recommends libpq-dev \
    && docker-php-ext-install pdo_pgsql \
    && rm -rf /var/lib/apt/lists/*
COPY php/uploads.ini /usr/local/etc/php/conf.d/uploads.ini
COPY public/ /var/www/html/
COPY src/ /var/www/src/
RUN mkdir -p /var/www/data/uploads && chown -R www-data:www-data /var/www/data
