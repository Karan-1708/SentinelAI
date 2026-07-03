FROM node:24-alpine AS build
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build \
 && rm -rf node_modules /root/.npm

FROM nginx:1.27-alpine
# Drop root — nginx will run under the "nginx" user and write only
# /var/cache/nginx and /var/run.
RUN apk add --no-cache curl \
 && chown -R nginx:nginx /var/cache/nginx /var/run
COPY --from=build --chown=nginx:nginx /app/dist /usr/share/nginx/html
COPY --chown=nginx:nginx nginx.conf /etc/nginx/conf.d/default.conf
USER nginx
EXPOSE 80
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD curl -fsS http://127.0.0.1/ >/dev/null || exit 1
