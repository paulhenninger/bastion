# The web server: the built SPA, served by nginx, which also proxies /api.
#
# Base images pinned to a version and digest (see the backend Dockerfile).
# Node stays on an LTS line (26); CI fails if this and ci.yml disagree.
FROM node:26.13.1-alpine@sha256:6bd9ab43c0ec0190ca7b2d193906cb8b7edf6e7f4afa43ddeccd6452710bffb5 AS build
WORKDIR /workspace
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts
COPY . .
RUN npm run build

# nginx built to run as an ordinary user (uid 101) on port 8080, on its stable
# branch (even minor: 1.30, 1.32 …); Dependabot proposes only patches here.
# Alpine's security fixes are applied as root, the only step that is.
FROM nginx/nginx-unprivileged:1.30.8-alpine@sha256:637c35e46af7bc0dd3d3bcf7162e004e13ab3b370fde7cd416e2ac410b5a985a
USER root
RUN apk upgrade --no-cache
USER 101
COPY nginx/nginx.conf /etc/nginx/nginx.conf
COPY nginx/trusted-proxies.conf /etc/nginx/trusted-proxies.conf
COPY nginx/security-headers.conf nginx/api-proxy.conf /etc/nginx/snippets/
COPY --from=build /workspace/dist /usr/share/nginx/html
EXPOSE 8080
HEALTHCHECK --interval=15s --timeout=3s --start-period=5s --retries=3 \
  CMD wget -q -O /dev/null http://127.0.0.1:8080/healthz || exit 1
# nginx itself, without the image's start-up scripts: they rewrite config files,
# which a read-only filesystem refuses.
ENTRYPOINT ["nginx", "-g", "daemon off;"]
