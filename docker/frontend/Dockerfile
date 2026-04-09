FROM node:20-alpine AS builder

WORKDIR /app

COPY frontend/package.json frontend/package-lock.json* ./
RUN npm install

COPY frontend/ ./
RUN npm run build

FROM node:20-alpine

WORKDIR /app

COPY --from=builder /app/package.json /app/package-lock.json* ./
RUN npm install --omit=dev

COPY --from=builder /app/.next ./.next
COPY --from=builder /app/next.config.js ./

ENV NODE_ENV=production
EXPOSE 3000

CMD ["npm", "start"]
