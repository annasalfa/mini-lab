# nginx/Dockerfile
FROM owasp/modsecurity-crs:nginx
# salin server block ke lokasi yang benar
COPY default.conf /etc/nginx/conf.d/default.conf
# override include CRS untuk ModSecurity
COPY modsecurity.conf /etc/modsecurity.d/include.conf
