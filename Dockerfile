FROM node:24-bookworm-slim
ENV NODE_ENV=production
WORKDIR /opt/flutifyps
RUN groupadd --gid 10001 flutifyps && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin flutifyps
COPY --chown=root:root package.json server.js config.json ./
COPY --chown=root:root lib ./lib
COPY --chown=root:root scripts/gen-env.js ./scripts/gen-env.js
USER 10001:10001
EXPOSE 8443
STOPSIGNAL SIGTERM
CMD ["node", "server.js"]
