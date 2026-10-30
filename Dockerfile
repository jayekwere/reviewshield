FROM node:24-bookworm-slim@sha256:c86ecead9e55a5210ac1727de38a4ca840bf03dcaf34dc9749addbf383b1920c AS web
WORKDIR /build
COPY package*.json ./
RUN npm ci --ignore-scripts
COPY . .
RUN npm run build
FROM node:24-bookworm-slim@sha256:c86ecead9e55a5210ac1727de38a4ca840bf03dcaf34dc9749addbf383b1920c
ENV NODE_ENV=production HOST=0.0.0.0
WORKDIR /app
RUN groupadd -g 10001 app && useradd -u 10001 -g app app
COPY package*.json ./
RUN npm ci --omit=dev --ignore-scripts
COPY --from=web /build/dist/src dist/src/
COPY --from=web /build/web web/
COPY samples/ samples/
RUN mkdir artifacts && chown 10001:10001 artifacts
USER 10001:10001
EXPOSE 8080
CMD ["node","dist/src/main.js"]
