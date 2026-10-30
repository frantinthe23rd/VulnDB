# tpscan runs untrusted JavaScript from every site it visits: treat it as a hostile
# workload. Disposable container, non-root user, no credentials or mounted secrets;
# each pass gets a fresh browser profile. Mount only an output directory.
FROM mcr.microsoft.com/playwright:v1.63.0-noble AS build
WORKDIR /app
COPY package.json package-lock.json tsconfig.json ./
RUN npm ci
COPY src ./src
COPY test ./test
RUN npx tsc -p tsconfig.json && npm prune --omit=dev

FROM mcr.microsoft.com/playwright:v1.63.0-noble
ENV NODE_ENV=production
WORKDIR /app
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/dist/src ./dist/src
COPY package.json ./
COPY assets ./assets
USER pwuser
WORKDIR /home/pwuser
ENTRYPOINT ["node", "/app/dist/src/cli.js"]
CMD ["--help"]
