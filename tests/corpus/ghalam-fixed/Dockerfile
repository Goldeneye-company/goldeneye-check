# GHALAM application image: PHP 8.3 + Apache, runs as www-data on port 8080.
# For reproducible builds pin the base image by digest (see README, section "Updates").
FROM php:8.3-apache-bookworm

RUN apt-get update \
    && apt-get install -y --no-install-recommends libpq-dev \
    && docker-php-ext-install pdo_pgsql \
    && rm -rf /var/lib/apt/lists/*

# Apache: remoteip module (real client IP from the trusted proxy), no extra modules,
# no version in headers and error pages, no TRACE method.
RUN a2enmod remoteip \
    && (a2dismod -f autoindex status || true) \
    && sed -ri \
        -e 's/^ServerTokens .*/ServerTokens Prod/' \
        -e 's/^ServerSignature .*/ServerSignature Off/' \
        -e 's/^TraceEnable .*/TraceEnable Off/' \
        /etc/apache2/conf-available/security.conf

COPY docker/apache/ports.conf /etc/apache2/ports.conf
COPY docker/apache/000-default.conf /etc/apache2/sites-available/000-default.conf

# PHP: the production profile plus own limits.
RUN cp "$PHP_INI_DIR/php.ini-production" "$PHP_INI_DIR/php.ini"
COPY docker/php/ghalam.ini "$PHP_INI_DIR/conf.d/zz-ghalam.ini"

# The code belongs to root and the application process cannot write to it.
COPY public/ /var/www/html/
COPY src/ /var/www/src/
COPY bin/ /var/www/bin/
RUN mkdir -p /var/www/data/uploads /var/www/data/tmp \
    && chown -R www-data:www-data /var/www/data \
    && chmod 0700 /var/www/data/uploads /var/www/data/tmp

USER www-data
EXPOSE 8080
