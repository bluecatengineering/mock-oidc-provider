FROM node:22-alpine AS build
COPY . /app
WORKDIR /app
RUN npm ci --omit=dev

FROM gcr.io/distroless/nodejs22-debian12
EXPOSE 80
EXPOSE 443
ENV PORT=80
COPY --from=build /app /app/
WORKDIR /app
CMD ["src/server.js"]
