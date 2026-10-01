# Build context is servers/ (the npm workspace), so @mcp-lab/shared is in scope:
#   docker build -f servers/scheduling/Dockerfile servers
# Build stage: compile TypeScript with dev dependencies present.
FROM node:24.21.0-slim AS build
WORKDIR /app
COPY package.json package-lock.json tsconfig.base.json ./
COPY shared/package.json shared/
COPY fhir-clinical/package.json fhir-clinical/
COPY scheduling/package.json scheduling/
RUN npm ci --ignore-scripts
COPY shared shared
COPY scheduling scheduling
RUN npx tsc -b scheduling

# Runtime stage: production deps + compiled output only, run as non-root.
FROM node:24.21.0-slim
WORKDIR /app
ENV NODE_ENV=production
COPY package.json package-lock.json ./
COPY shared/package.json shared/
COPY fhir-clinical/package.json fhir-clinical/
COPY scheduling/package.json scheduling/
RUN npm ci --omit=dev --ignore-scripts --workspace scheduling --include-workspace-root=false && npm cache clean --force
COPY --from=build /app/shared/dist shared/dist
COPY --from=build /app/scheduling/dist scheduling/dist
WORKDIR /app/scheduling
EXPOSE 3000
USER node
HEALTHCHECK --interval=15s --timeout=3s --start-period=10s --retries=3 \
  CMD ["node", "-e", "require('http').get('http://127.0.0.1:'+(process.env.PORT||3000)+'/.well-known/oauth-protected-resource/mcp',r=>process.exit(r.statusCode<500?0:1)).on('error',()=>process.exit(1))"]
CMD ["node", "dist/index.js"]
