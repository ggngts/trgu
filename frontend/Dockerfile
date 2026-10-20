# syntax=docker/dockerfile:1.7

FROM node:24-bookworm-slim AS build
WORKDIR /src

COPY package.json package-lock.json ./
RUN npm ci

COPY . .
RUN npm run build-only

FROM node:24-bookworm-slim AS runtime
WORKDIR /app

RUN npm install -g serve@14

COPY --from=build /src/dist ./dist

USER node
EXPOSE 801
CMD ["serve", "-s", "dist", "-l", "801"]
