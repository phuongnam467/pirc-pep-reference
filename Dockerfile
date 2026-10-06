FROM node:20-alpine

WORKDIR /app
COPY package.json ./
COPY src ./src
COPY app ./app

ENV NODE_ENV=production
ENV PORT=8787
EXPOSE 8787

CMD ["node", "app/server.mjs"]
