# Custom PHP image for the Piwigo PoC fixture.
# Built on the official php:8.2-apache image. Piwigo 17.0.0beta1 requires PHP 7.4+
# per its README; 8.2 is current stable and ships all the extensions Piwigo
# uses (mysqli, gd, exif, mbstring, xml, zip, fileinfo).
#
# The Piwigo code is bind-mounted into /var/www/html by docker-compose.

FROM php:8.2-apache

RUN apt-get update && apt-get install -y --no-install-recommends \
        libzip-dev \
        unzip \
        libpng-dev \
        libjpeg-dev \
        libfreetype-dev \
        libwebp-dev \
        libonig-dev \
        libxml2-dev \
    && docker-php-ext-configure gd --with-freetype --with-jpeg --with-webp \
    && docker-php-ext-install -j"$(nproc)" mysqli gd exif mbstring xml zip fileinfo \
    && docker-php-ext-enable opcache \
    && rm -rf /var/lib/apt/lists/*

# Apache config
RUN a2enmod rewrite headers
ENV APACHE_DOCUMENT_ROOT=/var/www/html
RUN sed -ri -e 's!/var/www/html!${APACHE_DOCUMENT_ROOT}!g' /etc/apache2/sites-available/*.conf \
    && sed -ri -e 's!/var/www/!${APACHE_DOCUMENT_ROOT}!g' /etc/apache2/apache2.conf /etc/apache2/conf-available/*.conf

# Sane PHP runtime defaults for the fixture: errors go to log, not the body
# (the PoCs do not need them; the audit findings do not depend on them).
RUN { \
        echo 'display_errors = Off'; \
        echo 'log_errors = On'; \
        echo 'error_reporting = E_ALL & ~E_DEPRECATED & ~E_STRICT'; \
        echo 'upload_max_filesize = 32M'; \
        echo 'post_max_size = 32M'; \
        echo 'opcache.enable = 1'; \
        echo 'opcache.validate_timestamps = 1'; \
        echo 'opcache.revalidate_freq = 0'; \
    } > /usr/local/etc/php/conf.d/piwigo-poc.ini

# The Piwigo writable dirs need to be owned by www-data; the named volumes
# come up root-owned by default, so an entrypoint chowns them on start.
COPY entrypoint.sh /usr/local/bin/piwigo-poc-entrypoint.sh
RUN chmod +x /usr/local/bin/piwigo-poc-entrypoint.sh

ENTRYPOINT ["/usr/local/bin/piwigo-poc-entrypoint.sh"]
CMD ["apache2-foreground"]

EXPOSE 80
