FROM node:20-alpine

WORKDIR /app
COPY package*.json ./
RUN npm install

COPY . .
RUN npm run build
RUN if [ -d public ]; then cp -r public .next/standalone/public; fi && cp -r .next/static .next/standalone/.next/static

EXPOSE 3000
CMD ["node", ".next/standalone/server.js"]
