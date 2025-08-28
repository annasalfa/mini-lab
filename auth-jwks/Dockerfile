FROM node:18-alpine
WORKDIR /app
COPY package.json .
RUN npm i --omit=dev
COPY server.js .
EXPOSE 8080
CMD ["node","server.js"]
