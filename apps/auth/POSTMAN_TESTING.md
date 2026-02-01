# Auth API Testing Guide - Postman

Complete step-by-step guide to test all authentication endpoints using Postman.

---

## Prerequisites

1. **Start the Auth Service**

   ```bash
   bun run start:auth
   # Server should be running on http://localhost:3001
   ```

2. **Ensure MongoDB is running**

   ```bash
   # Check if MongoDB is running
   mongosh
   ```

3. **Create `.env` file** in project root:
   ```env
   JWT_SECRET=your-super-secret-jwt-key
   JWT_REFRESH_SECRET=your-refresh-secret-key
   MONGODB_URI=mongodb://localhost:27017/ecommerce-auth
   PORT=3001
   ```

---

## Postman Setup

### Create Environment Variables

1. Click **Environments** → **Create Environment**
2. Name it: `Auth Service - Local`
3. Add these variables:

| Variable            | Initial Value           | Current Value           |
| ------------------- | ----------------------- | ----------------------- |
| `baseUrl`           | `http://localhost:3001` | `http://localhost:3001` |
| `accessToken`       |                         | (leave empty)           |
| `refreshToken`      |                         | (leave empty)           |
| `verificationToken` |                         | (leave empty)           |
| `resetToken`        |                         | (leave empty)           |
| `userId`            |                         | (leave empty)           |

4. Click **Save**
5. Select this environment from the dropdown (top right)

---

## Testing Flow

### 1. Register a New User

**Endpoint:** `POST {{baseUrl}}/auth/register`

**Headers:**

```
Content-Type: application/json
```

**Body (raw JSON):**

```json
{
  "email": "john.doe@example.com",
  "password": "SecurePass123!",
  "firstName": "John",
  "lastName": "Doe",
  "phone": "+1234567890"
}
```

**Expected Response (200 OK):**

```json
{
  "message": "Registration successful. Please check your email to verify your account."
}
```

**What to do next:**

1. Check your **terminal/console** where the auth service is running
2. Look for a log like: `[EMAIL] Verification token for john.doe@example.com: <TOKEN>`
3. **Copy the token** (it's a UUID like `a1b2c3d4-e5f6-7890-abcd-ef1234567890`)
4. In Postman, go to **Environments** → Select your environment
5. Set `verificationToken` to the copied token
6. Click **Save**

**Common Errors:**

| Status | Error                      | Solution                                                          |
| ------ | -------------------------- | ----------------------------------------------------------------- |
| 409    | User already exists        | Use a different email                                             |
| 400    | Password validation failed | Ensure password has uppercase, lowercase, and number/special char |
| 429    | Too many requests          | Wait 1 minute (rate limit: 3/min)                                 |

---

### 2. Verify Email

**Endpoint:** `POST {{baseUrl}}/auth/verify-email`

**Headers:**

```
Content-Type: application/json
```

**Body (raw JSON):**

```json
{
  "token": "{{verificationToken}}"
}
```

**Expected Response (200 OK):**

```json
{
  "message": "Email verified successfully. You can now login."
}
```

**Common Errors:**

| Status | Error                                 | Solution                                 |
| ------ | ------------------------------------- | ---------------------------------------- |
| 400    | Invalid or expired verification token | Get a new token via resend-verification  |
| 400    | Token already used                    | Email already verified, proceed to login |

---

### 3. Login

**Endpoint:** `POST {{baseUrl}}/auth/login`

**Headers:**

```
Content-Type: application/json
```

**Body (raw JSON):**

```json
{
  "email": "john.doe@example.com",
  "password": "SecurePass123!"
}
```

**Expected Response (200 OK):**

```json
{
  "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "user": {
    "id": "507f1f77bcf86cd799439011",
    "email": "john.doe@example.com",
    "firstName": "John",
    "lastName": "Doe",
    "role": "user",
    "permissions": [
      "profile:read",
      "profile:update",
      "orders:create",
      "orders:read:own",
      "products:read",
      "categories:read",
      "audit:read:own"
    ]
  }
}
```

**Auto-save tokens to environment:**

Add this to the **Tests** tab in Postman:

```javascript
if (pm.response.code === 200) {
  const response = pm.response.json();
  pm.environment.set('accessToken', response.accessToken);
  pm.environment.set('refreshToken', response.refreshToken);
  pm.environment.set('userId', response.user.id);
  console.log('✅ Tokens saved to environment');
}
```

**Common Errors:**

| Status | Error                    | Solution                          |
| ------ | ------------------------ | --------------------------------- |
| 401    | Invalid credentials      | Check email/password              |
| 401    | Please verify your email | Complete step 2 first             |
| 401    | Account is locked        | Wait 30 minutes or contact admin  |
| 429    | Too many requests        | Wait 1 minute (rate limit: 5/min) |

---

### 4. Get Current User Profile

**Endpoint:** `GET {{baseUrl}}/users/me`

**Headers:**

```
Authorization: Bearer {{accessToken}}
```

**Body:** None

**Expected Response (200 OK):**

```json
{
  "id": "507f1f77bcf86cd799439011",
  "email": "john.doe@example.com",
  "firstName": "John",
  "lastName": "Doe",
  "phone": "+1234567890",
  "role": "user",
  "status": "active",
  "emailVerified": true,
  "permissions": [
    "profile:read",
    "profile:update",
    "orders:create",
    "orders:read:own",
    "products:read",
    "categories:read",
    "audit:read:own"
  ],
  "lastLoginAt": "2024-02-01T10:30:00.000Z",
  "createdAt": "2024-02-01T10:00:00.000Z"
}
```

**Common Errors:**

| Status | Error        | Solution                               |
| ------ | ------------ | -------------------------------------- |
| 401    | Unauthorized | Token missing or invalid - login again |
| 403    | Forbidden    | Token expired - use refresh endpoint   |

---

### 5. Update Profile

**Endpoint:** `PATCH {{baseUrl}}/users/me`

**Headers:**

```
Authorization: Bearer {{accessToken}}
Content-Type: application/json
```

**Body (raw JSON):**

```json
{
  "firstName": "Jonathan",
  "phone": "+1987654321"
}
```

**Expected Response (200 OK):**

```json
{
  "id": "507f1f77bcf86cd799439011",
  "email": "john.doe@example.com",
  "firstName": "Jonathan",
  "lastName": "Doe",
  "phone": "+1987654321",
  "role": "user",
  "status": "active",
  "emailVerified": true,
  "permissions": [...],
  "lastLoginAt": "2024-02-01T10:30:00.000Z",
  "createdAt": "2024-02-01T10:00:00.000Z"
}
```

---

### 6. Get Active Sessions

**Endpoint:** `GET {{baseUrl}}/auth/sessions`

**Headers:**

```
Authorization: Bearer {{accessToken}}
```

**Expected Response (200 OK):**

```json
[
  {
    "id": "65b1c2d3e4f5a6b7c8d9e0f1",
    "ip": "127.0.0.1",
    "userAgent": "PostmanRuntime/7.36.0",
    "lastActive": "2024-02-01T10:30:00.000Z",
    "createdAt": "2024-02-01T10:30:00.000Z"
  }
]
```

---

### 7. Refresh Access Token

**Endpoint:** `POST {{baseUrl}}/auth/refresh`

**Headers:**

```
Content-Type: application/json
```

**Body (raw JSON):**

```json
{
  "refreshToken": "{{refreshToken}}"
}
```

**Expected Response (200 OK):**

```json
{
  "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "user": {
    "id": "507f1f77bcf86cd799439011",
    "email": "john.doe@example.com",
    "firstName": "Jonathan",
    "lastName": "Doe",
    "role": "user",
    "permissions": [...]
  }
}
```

**Auto-update tokens:**

Add to **Tests** tab:

```javascript
if (pm.response.code === 200) {
  const response = pm.response.json();
  pm.environment.set('accessToken', response.accessToken);
  pm.environment.set('refreshToken', response.refreshToken);
  console.log('✅ Tokens refreshed');
}
```

---

### 8. Change Password

**Endpoint:** `POST {{baseUrl}}/auth/change-password`

**Headers:**

```
Authorization: Bearer {{accessToken}}
Content-Type: application/json
```

**Body (raw JSON):**

```json
{
  "currentPassword": "SecurePass123!",
  "newPassword": "NewSecurePass456!"
}
```

**Expected Response (200 OK):**

```json
{
  "message": "Password changed successfully. Please login again."
}
```

**Note:** After changing password, all sessions are revoked. You must login again.

---

### 9. Forgot Password

**Endpoint:** `POST {{baseUrl}}/auth/forgot-password`

**Headers:**

```
Content-Type: application/json
```

**Body (raw JSON):**

```json
{
  "email": "john.doe@example.com"
}
```

**Expected Response (200 OK):**

```json
{
  "message": "If your email is registered, you will receive a password reset link."
}
```

**What to do next:**

1. Check terminal for: `[EMAIL] Password reset token for john.doe@example.com: <TOKEN>`
2. Copy the token
3. Set `resetToken` environment variable
4. Proceed to step 10

---

### 10. Reset Password

**Endpoint:** `POST {{baseUrl}}/auth/reset-password`

**Headers:**

```
Content-Type: application/json
```

**Body (raw JSON):**

```json
{
  "token": "{{resetToken}}",
  "newPassword": "BrandNewPass789!"
}
```

**Expected Response (200 OK):**

```json
{
  "message": "Password reset successful. Please login with your new password."
}
```

**Note:** All sessions are revoked. Login again with the new password.

---

### 11. Logout (Current Session)

**Endpoint:** `POST {{baseUrl}}/auth/logout`

**Headers:**

```
Authorization: Bearer {{accessToken}}
```

**Body:** None

**Expected Response (200 OK):**

```json
{
  "message": "Logged out successfully"
}
```

---

### 12. Logout All Devices

**Endpoint:** `POST {{baseUrl}}/auth/logout-all`

**Headers:**

```
Authorization: Bearer {{accessToken}}
```

**Body:** None

**Expected Response (200 OK):**

```json
{
  "message": "Logged out from all devices"
}
```

**Note:** This revokes ALL sessions. You must login again.

---

## Admin Endpoints

### 13. List All Users (Admin Only)

First, create an admin user by directly updating MongoDB:

```bash
mongosh
use ecommerce-auth
db.users.updateOne(
  { email: "john.doe@example.com" },
  { $set: { role: "admin" } }
)
```

Then login again to get admin permissions.

**Endpoint:** `GET {{baseUrl}}/users?page=1&limit=20`

**Headers:**

```
Authorization: Bearer {{accessToken}}
```

**Query Parameters:**

- `page` (optional): Page number (default: 1)
- `limit` (optional): Items per page (default: 20)
- `role` (optional): Filter by role (user, admin, restaurant, rider)
- `status` (optional): Filter by status (active, locked, suspended)

**Expected Response (200 OK):**

```json
{
  "users": [
    {
      "id": "507f1f77bcf86cd799439011",
      "email": "john.doe@example.com",
      "firstName": "Jonathan",
      "lastName": "Doe",
      "role": "admin",
      "status": "active",
      "emailVerified": true,
      "permissions": [...],
      "createdAt": "2024-02-01T10:00:00.000Z"
    }
  ],
  "total": 1,
  "page": 1,
  "limit": 20
}
```

---

### 14. Update User Role (Admin Only)

**Endpoint:** `PATCH {{baseUrl}}/users/{{userId}}/role`

**Headers:**

```
Authorization: Bearer {{accessToken}}
Content-Type: application/json
```

**Body (raw JSON):**

```json
{
  "role": "restaurant"
}
```

**Expected Response (200 OK):**

```json
{
  "id": "507f1f77bcf86cd799439011",
  "email": "john.doe@example.com",
  "firstName": "Jonathan",
  "lastName": "Doe",
  "role": "restaurant",
  "status": "active",
  "emailVerified": true,
  "permissions": [...],
  "createdAt": "2024-02-01T10:00:00.000Z"
}
```

---

### 15. Unlock User Account (Admin Only)

**Endpoint:** `PATCH {{baseUrl}}/users/{{userId}}/unlock`

**Headers:**

```
Authorization: Bearer {{accessToken}}
```

**Expected Response (200 OK):**

```json
{
  "id": "507f1f77bcf86cd799439011",
  "email": "john.doe@example.com",
  "firstName": "Jonathan",
  "lastName": "Doe",
  "role": "user",
  "status": "active",
  "emailVerified": true,
  "permissions": [...],
  "createdAt": "2024-02-01T10:00:00.000Z"
}
```

---

## Testing Account Lockout

To test the account lockout feature:

1. **Attempt 5 failed logins:**

**Endpoint:** `POST {{baseUrl}}/auth/login`

**Body:**

```json
{
  "email": "john.doe@example.com",
  "password": "WrongPassword123!"
}
```

Repeat this 5 times.

2. **On the 6th attempt:**

**Expected Response (401 Unauthorized):**

```json
{
  "statusCode": 401,
  "message": "Account is locked. Try again after 2024-02-01T11:00:00.000Z",
  "error": "Unauthorized"
}
```

3. **Wait 30 minutes** or use admin unlock endpoint

---

## Testing Rate Limiting

### Login Rate Limit (5 requests/minute)

Make 6 login requests within 1 minute:

**Expected Response on 6th request (429 Too Many Requests):**

```json
{
  "statusCode": 429,
  "message": "ThrottlerException: Too Many Requests"
}
```

### Register Rate Limit (3 requests/minute)

Make 4 registration requests within 1 minute:

**Expected Response on 4th request (429 Too Many Requests):**

```json
{
  "statusCode": 429,
  "message": "ThrottlerException: Too Many Requests"
}
```

---

## Postman Collection Export

Create a collection with all these requests:

1. Click **Collections** → **New Collection**
2. Name it: `Auth Service API`
3. Add all the requests above
4. Click **...** → **Export**
5. Save as `auth-api-collection.json`

---

## Troubleshooting

### Token Expired Error

**Error:**

```json
{
  "statusCode": 401,
  "message": "Unauthorized"
}
```

**Solution:** Use the refresh token endpoint (step 7) to get a new access token.

### MongoDB Connection Error

**Error in terminal:**

```
MongooseServerSelectionError: connect ECONNREFUSED 127.0.0.1:27017
```

**Solution:**

```bash
# Start MongoDB
brew services start mongodb-community
# OR
mongod --config /usr/local/etc/mongod.conf
```

### Port Already in Use

**Error in terminal:**

```
Error: listen EADDRINUSE: address already in use :::3001
```

**Solution:**

```bash
# Find and kill process on port 3001
lsof -ti:3001 | xargs kill -9
# Then restart
bun run start:auth
```

---

## Next Steps

- Test the Orders microservice endpoints
- Set up automated tests with Newman (Postman CLI)
- Create integration tests
- Set up CI/CD pipeline

---

## Additional Resources

- [Postman Documentation](https://learning.postman.com/)
- [JWT.io - Decode Tokens](https://jwt.io/)
- [Auth Service README](./README.md)
