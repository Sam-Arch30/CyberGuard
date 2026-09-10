# =====================================================================
# MailTrace AI - Frontend Service Dockerfile (Multi-Stage Build)
# =====================================================================

# Stage 1: Build static distribution bundle
FROM node:20-alpine AS builder

WORKDIR /app

# Install dependencies using package-lock for clean reproducible builds
COPY package*.json ./
RUN npm ci

# Copy frontend source code and build configurations
COPY src/ ./src/
COPY public/ ./public/
COPY index.html vite.config.ts tsconfig*.json ./

# Compile TypeScript and Vite production assets
RUN npm run build

# Stage 2: Serve production assets via Nginx
FROM nginx:alpine

# Copy compiled assets from builder stage
COPY --from=builder /app/dist /usr/share/nginx/html

# Copy custom Nginx configuration
COPY frontend/nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80

# Run Nginx in foreground
CMD ["nginx", "-g", "daemon off;"]
