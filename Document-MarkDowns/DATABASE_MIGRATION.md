# Database Migration Guide

## Overview

The Vulcan backend has been migrated from a local database (SQLite) to MongoDB. This guide helps you set up and verify the new database infrastructure.

---

## Prerequisites

- Docker and Docker Compose installed
- Python 3.9+
- `.env` file configured (use `.env.template` as reference)

---

## Step 1: Start MongoDB

### Using Docker Compose

```bash
# Navigate to project root
cd d:\final\Vulcan\vulcan-backend

# Start MongoDB container
docker-compose up -d

# Verify MongoDB is running
docker-compose ps
```

Expected output:
```
NAME                COMMAND                  SERVICE             STATUS
vulcan-mongo        "docker-entrypoint.s…"   mongo               Up 2 seconds
```

### Verify Connection

```bash
# Check MongoDB is accessible
docker-compose exec mongo mongosh -u vulcan_user -p secure_password_here --authenticationDatabase admin

# In mongosh shell:
> show databases
> exit
```

---

## Step 2: Configure Environment

### Create .env file

```bash
# Copy template
copy .env.template .env

# Or on Unix:
cp .env.template .env
```

### Edit .env with your values

```bash
# MongoDB Configuration
MONGO_HOST=localhost
MONGO_PORT=27017
MONGO_DB_NAME=vulcan
MONGO_USER=vulcan_user
MONGO_PASSWORD=secure_password_here

# JWT Security
JWT_SECRET=<your-super-secret-key>  # Change this!
JWT_ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=60

# Default Admin
DEFAULT_ADMIN_EMAIL=admin@vulcan.ai
DEFAULT_ADMIN_PASSWORD=admin123!
```

---

## Step 3: Install Dependencies

```bash
# Create virtual environment
python -m venv venv

# Activate it
# On Windows:
venv\Scripts\activate
# On Unix:
source venv/bin/activate

# Install packages
pip install -r requirements.txt
```

---

## Step 4: Start Backend

```bash
# Start development server
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

On startup, the application will:
1. ✅ Connect to MongoDB
2. ✅ Create required indexes
3. ✅ Seed default admin user (if not exists)
4. ✅ Start listening on http://localhost:8000

---

## Step 5: Verify Setup

### Health Check

```bash
curl http://localhost:8000/health
# Expected: {"status": "ok"}
```

### Register Test User

```bash
curl -X POST http://localhost:8000/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "testuser@example.com",
    "password": "testpass123",
    "full_name": "Test User"
  }'
```

Expected response:
```json
{
  "id": "507f1f77bcf86cd799439011",
  "email": "testuser@example.com",
  "full_name": "Test User",
  "role": "normal",
  "is_active": true,
  "is_superuser": false,
  "created_at": "2026-01-16T10:30:00"
}
```

### Login

```bash
curl -X POST http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "testuser@example.com",
    "password": "testpass123"
  }'
```

Expected response:
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer",
  "expires_in": 3600
}
```

### Get Current User

```bash
curl http://localhost:8000/api/v1/auth/me \
  -H "Authorization: Bearer <your_token_here>"
```

---

## Database Collections

The following MongoDB collections are automatically created:

### users

Stores user accounts and profiles.

```javascript
db.users.find({})
// Sample document:
{
  "_id": ObjectId("507f1f77bcf86cd799439011"),
  "email": "user@example.com",
  "hashed_password": "$2b$12$...",  // bcrypt hash
  "full_name": "John Doe",
  "role": "normal",
  "is_active": true,
  "created_at": ISODate("2026-01-16T10:30:00Z"),
  "updated_at": ISODate("2026-01-16T10:30:00Z")
}
```

**Indexes:**
- `email` - Unique, required for auth
- Created automatically on startup

### scans

Stores vulnerability scan records with user ownership.

```javascript
db.scans.find({})
// Sample document:
{
  "scan_id": "scan_507f1f77bcf8...",
  "user_id": "507f1f77bcf86cd799439011",  // User who initiated
  "repo_id": 123,
  "branch": "main",
  "mode": "DEEP",
  "state": "RUNNING",
  "progress": 45,
  "started_at": ISODate("2026-01-16T10:30:00Z"),
  "finished_at": null,
  "created_at": ISODate("2026-01-16T10:30:00Z"),
  "updated_at": ISODate("2026-01-16T10:31:00Z")
}
```

**Indexes:**
- `scan_id` - Unique, for retrieving specific scans
- `user_id` - For user-scoped queries
- Created automatically on startup

---

## Data Persistence

### Docker Volume

MongoDB data is persisted in a named Docker volume:

```bash
# List volumes
docker volume ls

# Inspect vulcan-mongo volume
docker volume inspect vulcan-mongo

# Location on Windows: C:\ProgramData\Docker\volumes\vulcan-mongo\_data
# Location on Linux: /var/lib/docker/volumes/vulcan-mongo/_data
```

### Backup

```bash
# Export MongoDB data
docker-compose exec mongo mongodump -u vulcan_user -p secure_password_here \
  --authenticationDatabase admin \
  --out /backup

# Restore from backup
docker-compose exec mongo mongorestore -u vulcan_user -p secure_password_here \
  --authenticationDatabase admin \
  /backup
```

---

## Troubleshooting

### MongoDB Connection Failed

```
ERROR: Could not connect to MongoDB
```

**Solutions:**
1. Check MongoDB is running: `docker-compose ps`
2. Verify credentials in .env match docker-compose.yml
3. Check port 27017 is not in use: `netstat -an | grep 27017`
4. Restart MongoDB: `docker-compose restart mongo`

### User Not Found After Registration

This usually indicates MongoDB is not properly connected.

```bash
# Check MongoDB is running
docker-compose logs mongo

# Verify connection
docker-compose exec mongo mongosh -u vulcan_user -p <password> --authenticationDatabase admin
```

### Admin User Not Created

The default admin user is seeded on first startup.

```bash
# Check if admin exists
docker-compose exec mongo mongosh -u vulcan_user -p <password> --authenticationDatabase admin vulcan

# In mongosh:
> db.users.findOne({"email": "admin@vulcan.ai"})

# If missing, restart backend to re-seed
```

### JWT Token Issues

```
ERROR: Invalid token
```

**Solutions:**
1. Ensure JWT_SECRET is set in .env
2. Token may be expired (check expires_in value)
3. Use `/auth/refresh` to get new token
4. Verify Bearer token format: `Authorization: Bearer <token>`

---

## MongoDB Management

### Connect to MongoDB Shell

```bash
# Using docker-compose
docker-compose exec mongo mongosh -u vulcan_user -p secure_password_here --authenticationDatabase admin

# Common commands:
show databases
use vulcan
show collections
db.users.find()
db.scans.countDocuments()
db.users.updateOne({email: "admin@vulcan.ai"}, {$set: {role: "admin"}})
```

### Drop All Data (Development Only)

```bash
docker-compose exec mongo mongosh -u vulcan_user -p secure_password_here --authenticationDatabase admin

# In mongosh:
> use vulcan
> db.dropDatabase()
```

### View Indexes

```bash
docker-compose exec mongo mongosh -u vulcan_user -p secure_password_here --authenticationDatabase admin vulcan

# In mongosh:
> db.users.getIndexes()
> db.scans.getIndexes()
```

---

## Migration from SQLite (If Applicable)

If you previously used SQLite:

1. **Export old user data** - Extract from SQLite if needed
2. **Transform format** - Convert to MongoDB document format
3. **Import to MongoDB** - Use `mongoimport` or scripts
4. **Verify indexes** - Ensure indexes are created
5. **Test auth flow** - Verify users can login with migrated passwords

---

## Security Checklist

- [ ] Changed JWT_SECRET from default value
- [ ] Updated MONGO_PASSWORD from default
- [ ] MongoDB only binds to localhost (127.0.0.1)
- [ ] .env file is in .gitignore
- [ ] No credentials in git history
- [ ] Admin default password changed after first login
- [ ] HTTPS enabled in production (via reverse proxy)

---

## Next Steps

1. ✅ MongoDB running and initialized
2. ✅ Backend connected and seeding data
3. ✅ Users can register and login
4. ✅ Scans stored with user ownership
5. → Proceed with application-level features

---

For issues or questions, check `REFACTORING_COMPLETE.md` for architecture details.
