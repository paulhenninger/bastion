# The web server: the built SPA, served by nginx, which also proxies /api.
#
# Base images pinned to a version and digest (see the backend Dockerfile).
# Node stays on an LTS line (26); CI fails if this and ci.yml disagree.
FROM node:26.13.0-alpine@sha256:c6ad9e9c1d80f6eb607c26b4b0a132ff7a2344fad1c78ea3baa2a7d4c8de6d94 AS build
WORKDIR /workspace
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts
COPY . .
RUN npm run build

# nginx built to run as an ordinary user (uid 101) on port 8080, on its stable
# branch (even minor: 1.30, 1.32 …); Dependabot proposes only patches here.
# Alpine's security fixes are applied as root, the only step that is.
FROM nginxinc/nginx-unprivileged:1.30.6-alpine@sha256:f5116ed4606f3eb015dd4a8e28cb9b351476dc0ad4bc6e9f93b19cec130cdf03
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
