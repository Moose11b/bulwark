FROM node:20-alpine

RUN apk add --no-cache libc6-compat

WORKDIR /app

COPY package.json ./
RUN npm install --legacy-peer-deps

COPY . .

ENV NODE_ENV=development
ENV NEXT_TELEMETRY_DISABLED=1

EXPOSE 3000

CMD ["npm", "run", "dev"]
