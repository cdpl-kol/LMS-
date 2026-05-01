FROM node:18-alpine

WORKDIR /app

# Install backend dependencies
COPY backend/package*.json ./backend/
RUN cd backend && npm install --production

# Copy all project files (HTML, assets, backend)
COPY . .

EXPOSE 8080

CMD ["node", "backend/server.js"]
