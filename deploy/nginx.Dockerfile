FROM nginx:1.25-alpine
COPY edge-gateway/nginx.conf /etc/nginx/nginx.conf
COPY challenge-page /usr/share/nginx/html
