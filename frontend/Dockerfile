# syntax=docker/dockerfile:1.7

FROM node:24-bookworm-slim AS build
WORKDIR /src

COPY package.json package-lock.json ./
RUN npm ci

COPY . .
RUN npm run build-only

FROM nginx:1.27-alpine AS runtime

RUN rm -rf /usr/share/nginx/html/* /etc/nginx/conf.d/default.conf

COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /src/dist /usr/share/nginx/html

EXPOSE 800
CMD ["nginx", "-g", "daemon off;"]
