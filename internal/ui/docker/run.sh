#!/bin/sh

# Configuration
cat >/usr/share/nginx/html/config.json <<EOF
{
  "default_service_url": "${INTERNAL_API_URL-https://localhost:3443}",
  "default_ui_url": "${INTERNAL_UI_URL-https://localhost:3000}"
}
EOF

# Setup nginx configuration based on user inputs
cat >/tmp/nginx.conf <<EOF
load_module /etc/nginx/modules/ndk_http_module.so;
load_module /etc/nginx/modules/ngx_http_lua_module.so;

worker_processes auto;
daemon off;
pid /tmp/nginx.pid;

events {
    worker_connections  1024;
}

http {
    lua_package_path "/usr/local/lib/lua/?.lua;;";

    include             /etc/nginx/mime.types;
    sendfile            on;
    keepalive_timeout   65;
    gzip                on;
    access_log          off;

    large_client_header_buffers 4 1024k;
    client_header_buffer_size 256k;

    server {
        listen        1080;
        server_name   localhost;
        return        301 https://\$host\$request_uri;
    }

    server {
        listen       1443 ssl default_server;
        server_name  _;

        if (-d \$request_filename) {
            rewrite [^/]\$ \$scheme://\$http_host\$uri/ permanent;
        }

        ssl_certificate                   "$FRONTEND_TLS_CERT";
        ssl_certificate_key               "$FRONTEND_TLS_KEY";
        ssl_password_file                 "$FRONTEND_TLS_KEY_PASS";
        ssl_session_cache                 shared:SSL:1140m;
        ssl_session_timeout               1140m;
        ssl_protocols                     TLSv1.2;
        ssl_ciphers                       ECDHE+AESGCM:EECDH+AESGCM:ECDH+AESGCM:ECDH+AES256:HIGH:!aNULL:!eNULL:!LOW:!RC4:!3DES:!MD5:!EXP:!PSK:!SRP:!DSS;
        ssl_prefer_server_ciphers         on;

        root   /usr/share/nginx/html;
        index  index.html index.htm;

        location ~* \.(?:html?)$ {
            expires 2d;
            add_header Cache-Control                "no-cache, must-revalidate";
            add_header Pragma                       "no-cache";
            add_header Strict-Transport-Security    'max-age=31536000; includeSubDomains; preload' always;
            add_header X-Frame-Options              DENY always;
            add_header X-Content-Type-Options       nosniff always;
            add_header X-XSS-Protection             "1; mode=block" always;
        }

        location ~* \.(?:manifest|appcache|xml|json)$ {
            expires 2d;
            add_header Cache-Control "public";
            add_header Strict-Transport-Security 'max-age=31536000; includeSubDomains; preload' always;
            add_header X-Frame-Options DENY always;
            add_header X-Content-Type-Options nosniff always;
            add_header X-XSS-Protection "1; mode=block" always;
        }

        location ~* \.(?:css)$ {
            try_files \$uri =404;
            add_header Cache-Control "public";
            add_header Strict-Transport-Security 'max-age=31536000; includeSubDomains; preload' always;
            add_header X-Frame-Options DENY always;
            add_header X-Content-Type-Options nosniff always;
            add_header X-XSS-Protection "1; mode=block" always;
        }

        location ~* \.(?:js)$ {
            try_files \$uri =404;
            expires 2d;
            add_header Cache-Control "public";
            add_header Strict-Transport-Security 'max-age=31536000; includeSubDomains; preload' always;
            add_header X-Frame-Options DENY always;
            add_header X-Content-Type-Options nosniff always;
            add_header X-XSS-Protection "1; mode=block" always;
        }

        location ~ ^.+\..+$ {
            try_files \$uri =404;
            add_header Strict-Transport-Security 'max-age=31536000; includeSubDomains; preload' always;
            add_header X-Frame-Options DENY always;
            add_header X-Content-Type-Options nosniff always;
            add_header X-XSS-Protection "1; mode=block" always;
        }

        location / {
            try_files \$uri \$uri/ /index.html;
            add_header Strict-Transport-Security 'max-age=31536000; includeSubDomains; preload' always;
            add_header X-Frame-Options DENY always;
            add_header X-Content-Type-Options nosniff always;
            add_header X-XSS-Protection "1; mode=block" always;
        }

        location ~*/saml/callback {
            content_by_lua_block {
                ngx.req.read_body()
                local args, err = ngx.req.get_post_args()
                if not args then
                    ngx.log(ngx.ERR, "failed to get post args: ", err)
                    return
                end

                local samlResponse = args.SAMLResponse
                local relayState = args.RelayState

                if samlResponse and relayState then
                    local newUrl = "/saml-verify?" .. "SAMLResponse=" .. samlResponse .. "&relayState=" .. relayState
                    ngx.redirect(newUrl)
                end
            }
        }
    }
}
EOF

exec nginx -c "/tmp/nginx.conf"
