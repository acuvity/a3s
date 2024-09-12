FROM alpine as builder

RUN apk add --no-cache \
    gcc \
    libc-dev \
    make \
    pcre-dev \
    zlib-dev \
    git \
    luajit \
    pcre \
    pcre-dev \
    perl \
    openssl-dev

WORKDIR /tmp

ENV LUA_PATH "/usr/local/lib/lua/?.lua;;"
ENV LUA_CPATH "/usr/local/lib/lua/?.so;;"

ENV LUAJIT_LIB=/usr/local/lib
ENV LUAJIT_INC=/usr/local/include/luajit-2.1

# Download sources
RUN wget "https://freenginx.org/download/freenginx-1.26.0.tar.gz" \
    && wget "https://github.com/simplresty/ngx_devel_kit/archive/v0.3.1.tar.gz" \
    && wget "https://openresty.org/download/openresty-1.21.4.3.tar.gz" \
    && wget "https://github.com/openresty/lua-nginx-module/archive/refs/tags/v0.10.26.tar.gz" \
    && wget "https://github.com/openresty/luajit2/archive/refs/tags/v2.1-20240314.tar.gz" \
    && wget "https://github.com/openresty/lua-resty-lrucache/archive/refs/tags/v0.13.tar.gz" \
    && wget "https://github.com/openresty/lua-resty-core/archive/refs/tags/v0.1.28.tar.gz"

# Extract sources
RUN tar -xzf freenginx-1.26.0.tar.gz \
    && tar -xzf v0.3.1.tar.gz \
    && tar -xzf v0.10.26.tar.gz \
    && tar -xzf v2.1-20240314.tar.gz \
    && tar -xzf openresty-1.21.4.3.tar.gz \
    && tar -xzf v0.13.tar.gz \
    && tar -xzf v0.1.28.tar.gz

RUN cd luajit2-2.1-20240314 \
    && make \
    && make install

RUN cd openresty-1.21.4.3 \
    && ./configure -j2 \
    && make -j2 \
    && make install

RUN cd lua-resty-lrucache-0.13 \
    && make \
    && make install

RUN cd lua-resty-core-0.1.28 \
    && make install

# Build nginx with the modules
RUN cd freenginx-1.26.0 \
    && ./configure --with-compat --add-dynamic-module=../ngx_devel_kit-0.3.1 --add-dynamic-module=../lua-nginx-module-0.10.26 --with-ld-opt="-lpcre -Wl,-rpath,/usr/local/lib:/usr/lib" \
    && make \
    && make install

FROM nginx:stable-alpine

COPY --from=builder /usr/local/share/lua/ /usr/local/share/lua/
COPY --from=builder /usr/local/nginx/modules /etc/nginx/modules
COPY --from=builder /usr/local/lib /usr/local/lib
COPY build /usr/share/nginx/html
COPY run.sh /run.sh

RUN addgroup -g 1001 internal && adduser -u 1001 -H -D -G internal internal \
    && chown -R internal:internal /usr/share/nginx/ \
    && chown -R internal:internal /var/cache/nginx/ \
    && apk add --no-cache libgcc pcre pcre-dev

EXPOSE 1443

ENTRYPOINT ["/run.sh"]
