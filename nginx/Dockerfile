# nginx/Dockerfile
FROM owasp/modsecurity-crs:nginx

# Pakai mekanisme template bawaan image:
# entrypoint akan menulis ke /etc/nginx/conf.d/default.conf
COPY default.conf /etc/nginx/templates/conf.d/default.conf.template

# Tambahkan aturan ModSecurity (override CRS)
COPY modsecurity.conf /etc/nginx/templates/modsecurity.d/modsecurity-override.conf.template
