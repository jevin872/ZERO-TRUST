FROM node:20-alpine

WORKDIR /app

# Copy package configurations and install dependencies
COPY package.json ./
RUN npm install

# Copy source code files
COPY . .

# Expose Vite dev server port
EXPOSE 5173

# Run development server with host flag to allow docker networking
CMD ["npm", "run", "dev", "--", "--host"]
