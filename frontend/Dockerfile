# Build the SPA, serve it with an unprivileged nginx (which also proxies /api).
FROM node:24-alpine AS build
WORKDIR /workspace
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts
COPY . .
RUN npm run build

# Runs as the "nginx" user on port 8080: no root process in the container.
FROM nginxinc/nginx-unprivileged:stable-alpine
COPY nginx/default.conf /etc/nginx/conf.d/default.conf
COPY nginx/security-headers.conf nginx/api-proxy.conf /etc/nginx/snippets/
COPY --from=build /workspace/dist /usr/share/nginx/html
EXPOSE 8080
