# User Management and HTTPS Support

This document describes the user management features and HTTPS support added to subScraper.

## User Management

### Overview

SubScraper now includes comprehensive user management capabilities allowing administrators to create, edit, and delete user accounts. All user management operations require admin privileges.

### Features

#### Creating Users

1. **Via Web UI:**
   - Navigate to Settings → Users tab
   - Fill in the create user form:
     - Username (min 3 characters, alphanumeric + underscore/hyphen only)
     - Password (min 6 characters)
     - Confirm password
     - Admin checkbox (grants full access)
   - Click "Create User"

2. **Programmatically:**
   ```bash
   curl -X POST http://127.0.0.1:8342/api/users/create \
     -H "Content-Type: application/json" \
     -H "Cookie: session_token=YOUR_SESSION_TOKEN" \
     -d '{
       "username": "newuser",
       "password": "password123",
       "is_admin": false
     }'
   ```

#### Editing Users

Edit existing users to change their username, password, or admin status:

1. **Via Web UI:**
   - Navigate to Settings → Users tab
   - Click "Edit" button next to the user
   - Follow the prompts to update:
     - Username (leave empty to keep current)
     - Password (leave empty to keep current)
     - Admin status (click OK to toggle)

2. **Programmatically:**
   ```bash
   curl -X POST http://127.0.0.1:8342/api/users/edit \
     -H "Content-Type: application/json" \
     -H "Cookie: session_token=YOUR_SESSION_TOKEN" \
     -d '{
       "user_id": 2,
       "username": "updatedname",
       "password": "newpassword",
       "is_admin": true
     }'
   ```

#### Deleting Users

Remove users that are no longer needed:

1. **Via Web UI:**
   - Navigate to Settings → Users tab
   - Click "Delete" button next to the user
   - Confirm the deletion

2. **Programmatically:**
   ```bash
   curl -X POST http://127.0.0.1:8342/api/users/delete \
     -H "Content-Type: application/json" \
     -H "Cookie: session_token=YOUR_SESSION_TOKEN" \
     -d '{
       "user_id": 2
     }'
   ```

### Security Features

- **Last Admin Protection:** The system prevents deletion of the last admin user and removal of admin privileges from the last admin
- **Password Hashing:** All passwords are hashed using PBKDF2-HMAC-SHA256 with 100,000 iterations
- **Input Validation:** Usernames and passwords are validated for length and format
- **Admin-Only Access:** All user management operations require admin authentication

### API Endpoints

All endpoints require authentication and admin privileges:

- `POST /api/users/create` - Create a new user
- `POST /api/users/edit` - Update an existing user
- `POST /api/users/delete` - Delete a user
- `GET /api/users` - List all users

## HTTPS Support

### Overview

SubScraper can now be served over HTTPS with support for both self-signed certificates (for development/testing) and custom certificates (for production).

### Usage

#### Quick Start with Auto-Generated Certificate

The simplest way to enable HTTPS is to use the `--https` flag, which will automatically generate a self-signed certificate:

```bash
python3 main.py --https
```

This will:
1. Generate a self-signed certificate valid for 365 days
2. Save the certificate and key in `recon_data/server.crt` and `recon_data/server.key`
3. Start the server with HTTPS on port 8342
4. Display the HTTPS URL: `https://0.0.0.0:8342`

**Note:** Browsers will show a security warning for self-signed certificates. This is expected and safe for local development.

#### Using Custom Certificates

For production deployments, provide your own certificate and key files:

```bash
python3 main.py --https --cert /path/to/certificate.crt --key /path/to/private.key
```

#### Obtaining Production Certificates

For production use, obtain a certificate from a trusted Certificate Authority (CA):

1. **Let's Encrypt (Free):**
   ```bash
   # Install certbot
   sudo apt-get install certbot  # Ubuntu/Debian
   
   # Generate certificate
   sudo certbot certonly --standalone -d your-domain.com
   
   # Use the generated certificate
   python3 main.py --https \
     --cert /etc/letsencrypt/live/your-domain.com/fullchain.pem \
     --key /etc/letsencrypt/live/your-domain.com/privkey.pem
   ```

2. **Commercial CA:** Follow your CA's instructions to generate a Certificate Signing Request (CSR) and obtain your certificate.

### Certificate Requirements

- **OpenSSL:** The self-signed certificate generation requires OpenSSL to be installed
  - Ubuntu/Debian: `sudo apt-get install openssl`
  - macOS: `brew install openssl` (usually pre-installed)
  - Windows: Download from https://slproweb.com/products/Win32OpenSSL.html

### HTTPS Options

```
--https               Enable HTTPS with self-signed certificate (auto-generated)
--cert CERT          Path to SSL certificate file
--key KEY            Path to SSL private key file
```

### Examples

1. **Development (self-signed certificate):**
   ```bash
   python3 main.py --https --host 127.0.0.1 --port 8443
   ```

2. **Production (Let's Encrypt certificate):**
   ```bash
   python3 main.py --https \
     --cert /etc/letsencrypt/live/recon.example.com/fullchain.pem \
     --key /etc/letsencrypt/live/recon.example.com/privkey.pem \
     --host 0.0.0.0 --port 443
   ```

3. **Local network access:**
   ```bash
   python3 main.py --https --host 0.0.0.0 --port 8342
   # Access from other devices: https://your-ip-address:8342
   ```

### Troubleshooting

#### Browser Security Warnings

When using self-signed certificates, browsers will display security warnings. This is normal and expected. To proceed:

- **Chrome/Edge:** Click "Advanced" → "Proceed to localhost (unsafe)"
- **Firefox:** Click "Advanced" → "Accept the Risk and Continue"
- **Safari:** Click "Show Details" → "visit this website"

For development purposes, you can add the self-signed certificate to your system's trusted certificate store.

#### Certificate Not Found

If you see "Certificate file not found" errors:
- Verify the paths provided with `--cert` and `--key` are correct
- Ensure the files are readable by the user running the application
- Check that the certificate files exist and are not empty

#### OpenSSL Not Found

If certificate generation fails with "OpenSSL not found":
- Install OpenSSL using your package manager
- Verify installation with: `openssl version`
- Alternatively, provide your own certificate with `--cert` and `--key`

#### Port Already in Use

If port 443 (standard HTTPS port) is already in use:
- Use a different port: `--port 8443`
- Or stop the service using port 443
- Note: Ports below 1024 require root/administrator privileges

### Security Best Practices

1. **Use Trusted Certificates in Production:** Always use certificates from a trusted CA for production deployments
2. **Keep Certificates Updated:** Monitor certificate expiration dates and renew before they expire
3. **Protect Private Keys:** Ensure private key files have restricted permissions (chmod 600)
4. **Use Strong Ciphers:** The application uses Python's default TLS configuration which includes strong ciphers
5. **Regular Updates:** Keep OpenSSL and Python updated to get the latest security patches

### HTTP vs HTTPS

Both HTTP and HTTPS modes are fully functional:

- **HTTP Mode (Default):** `python3 main.py` - Simpler setup, suitable for local development
- **HTTPS Mode:** `python3 main.py --https` - Encrypted traffic, required for production deployments

All features (authentication, user management, job control, etc.) work identically in both modes.
