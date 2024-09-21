#!/bin/bash

# generate_letsencrypt_cert.sh

# Variables
DOMAIN=""
NGINX_CONF_DIR="/etc/nginx"
SITES_AVAILABLE_DIR="$NGINX_CONF_DIR/sites-available"
SITES_ENABLED_DIR="$NGINX_CONF_DIR/sites-enabled"
APP_CONF="email-blaze"
APP_PORT="8080"

# Check if script is run as root
if [ "$EUID" -ne 0 ]; then
	echo "Please run as root"
	exit 1
fi

# Function to install Certbot
install_certbot() {
	apt update
	apt install -y certbot python3-certbot-nginx
}

# Main script
echo "Let's Encrypt Certificate Generator for Email Blaze"

# Check if Certbot is installed
if ! command -v certbot &>/dev/null; then
	echo "Certbot not found. Installing..."
	install_certbot
else
	echo "Certbot is already installed."
fi

# Prompt for domain
read -p "Enter your domain (e.g., example.com): " DOMAIN

# Verify Nginx is installed
if ! command -v nginx &>/dev/null; then
	echo "Nginx not found. Please install Nginx before running this script."
	exit 1
fi

# Stop Nginx
echo "Stopping Nginx..."
systemctl stop nginx

# Obtain the certificate
echo "Obtaining Let's Encrypt certificate for $DOMAIN..."
certbot certonly --standalone -d "$DOMAIN" -d "www.$DOMAIN"

# Start Nginx
echo "Starting Nginx..."
systemctl start nginx

# Update Nginx configuration
echo "Updating Nginx configuration..."
cat >"$SITES_AVAILABLE_DIR/$APP_CONF" <<EOF
server {
    listen 80;
    server_name $DOMAIN www.$DOMAIN;
    return 301 https://\$server_name\$request_uri;
}

server {
    listen 443 ssl http2;
    server_name $DOMAIN www.$DOMAIN;

    ssl_certificate /etc/letsencrypt/live/$DOMAIN/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$DOMAIN/privkey.pem;

    # Add SSL parameters here for better security (optional)
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;

    # HSTS (optional)
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

    location / {
        proxy_pass http://localhost:$APP_PORT;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}
EOF

# Enable the site
ln -sf "$SITES_AVAILABLE_DIR/$APP_CONF" "$SITES_ENABLED_DIR/"

# Test Nginx configuration
nginx -t

# Reload Nginx
systemctl reload nginx

echo "Certificate obtained and Nginx configured for HTTPS."
echo "Don't forget to update your firewall rules if necessary:"
echo "sudo ufw allow 'Nginx Full'"
echo "sudo ufw delete allow 'Nginx HTTP'"

echo "Certificate renewal is automatic. You can test it with:"
echo "sudo certbot renew --dry-run"
