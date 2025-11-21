FROM node:20-slim

WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm ci

# Copy source
COPY . .

# Expose Vite dev server port
EXPOSE 5173

# Run dev server
CMD ["npm", "run", "dev", "--", "--host", "0.0.0.0"]
