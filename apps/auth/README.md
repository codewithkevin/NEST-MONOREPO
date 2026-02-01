# Auth Microservice

A production-grade authentication and authorization system built with NestJS, implementing enterprise security patterns.

---

## Table of Contents

1. [Quick Start](#quick-start)
2. [Architecture Overview](#architecture-overview)
3. [Core Concepts Explained](#core-concepts-explained)
   - [JWT Authentication](#jwt-authentication)
   - [Guards](#guards)
   - [Decorators](#decorators)
   - [Permissions System](#permissions-system)
4. [Security Features](#security-features)
5. [API Reference](#api-reference)
6. [Database Schema](#database-schema)

---

## Quick Start

### 1. Environment Setup

Create a `.env` file in the project root:

```env
JWT_SECRET=your-super-secret-jwt-key-change-in-production
JWT_REFRESH_SECRET=your-refresh-secret-key-change-in-production
MONGODB_URI=mongodb://localhost:27017/ecommerce-auth
PORT=3001
```

### 2. Start the Service

```bash
bun run start:auth
# Server runs on http://localhost:3001
```

### 3. Test Registration

```bash
curl -X POST http://localhost:3001/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "SecurePass123!",
    "firstName": "John",
    "lastName": "Doe"
  }'
```

---

## Architecture Overview

```
apps/auth/src/
├── auth/           # Pure authentication (login, tokens, sessions)
├── users/          # User profile management (CRUD)
├── permissions/    # Fine-grained RBAC
├── security/       # Rate limiting, lockout, audit
└── common/         # Shared enums, utilities
```

### Why This Structure?

| Module           | Responsibility                                    |
| ---------------- | ------------------------------------------------- |
| **auth/**        | Handles login, logout, token generation, sessions |
| **users/**       | Manages user profiles, not authentication logic   |
| **permissions/** | Role-based and permission-based access control    |
| **security/**    | Audit logs, login attempts, token blacklisting    |

---

## Core Concepts Explained

### JWT Authentication

**JWT (JSON Web Token)** is a compact, URL-safe way to represent claims between two parties.

#### How It Works

```
┌─────────┐        ┌─────────┐        ┌─────────┐
│  User   │──1──▶  │  Auth   │──2──▶  │   DB    │
│ (Login) │        │ Service │        │(Verify) │
└─────────┘        └─────────┘        └─────────┘
     ▲                  │
     │                  │ 3. Generate JWT
     │                  ▼
     │            ┌─────────┐
     └───4────────│  Token  │
       (Return)   └─────────┘
```

1. User sends email + password
2. Auth service verifies credentials against database
3. If valid, generates a JWT token
4. Returns token to user

#### JWT Structure

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.  ← Header (algorithm)
eyJzdWIiOiIxMjM0NTY3ODkwIiwiZW1haWwiOiJ1c2VyQGV4YW1wbGUuY29tIiwicm9sZSI6InVzZXIifQ.  ← Payload
SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c  ← Signature
```

**Payload contains:**

```json
{
  "sub": "user-id-here", // Subject (user ID)
  "email": "user@example.com",
  "role": "user",
  "jti": "unique-token-id", // Used for blacklisting
  "iat": 1706760000, // Issued at
  "exp": 1706760900 // Expires at (15 min later)
}
```

#### Why Two Tokens?

| Token             | Lifetime   | Purpose                                        |
| ----------------- | ---------- | ---------------------------------------------- |
| **Access Token**  | 15 minutes | Short-lived, sent with every request           |
| **Refresh Token** | 7 days     | Long-lived, used only to get new access tokens |

**Security Benefit**: If an access token is stolen, it's only valid for 15 minutes. The refresh token is stored more securely and rarely transmitted.

---

### Guards

**Guards** in NestJS are like security checkpoints. They decide whether a request should proceed or be rejected.

```
Request → Guard 1 → Guard 2 → Guard 3 → Controller
              ↓         ↓         ↓
           (Check)  (Check)   (Check)
              ↓         ↓         ↓
           Pass?     Pass?    Pass?
```

#### Our Guards

##### 1. JwtAuthGuard

**File:** `auth/guards/jwt-auth.guard.ts`

```typescript
@Injectable()
export class JwtAuthGuard extends AuthGuard('jwt') {
  canActivate(context: ExecutionContext) {
    // Check if route is marked as @Public()
    const isPublic = this.reflector.getAllAndOverride<boolean>(IS_PUBLIC_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);

    if (isPublic) {
      return true; // Skip authentication for public routes
    }

    return super.canActivate(context); // Validate JWT
  }
}
```

**What it does:**

- Extracts JWT from `Authorization: Bearer <token>` header
- Validates the token signature and expiration
- Attaches user info to `request.user`
- Skips validation for routes marked with `@Public()`

##### 2. RolesGuard

**File:** `auth/guards/roles.guard.ts`

```typescript
@Injectable()
export class RolesGuard implements CanActivate {
  canActivate(context: ExecutionContext): boolean {
    const requiredRoles = this.reflector.getAllAndOverride<UserRole[]>(
      ROLES_KEY,
      [context.getHandler(), context.getClass()],
    );

    if (!requiredRoles) {
      return true; // No role restriction
    }

    const { user } = context.switchToHttp().getRequest();
    return requiredRoles.some((role) => user.role === role);
  }
}
```

**What it does:**

- Checks if the endpoint requires specific roles (via `@Roles()` decorator)
- Compares user's role against required roles
- Allows if user has ANY of the required roles

##### 3. PermissionsGuard

**File:** `auth/guards/permissions.guard.ts`

```typescript
@Injectable()
export class PermissionsGuard implements CanActivate {
  canActivate(context: ExecutionContext): boolean {
    const requiredPermissions = this.reflector.getAllAndOverride<string[]>(
      PERMISSIONS_KEY,
      [context.getHandler(), context.getClass()],
    );

    if (!requiredPermissions) {
      return true;
    }

    const { user } = context.switchToHttp().getRequest();
    return requiredPermissions.some((permission) =>
      user.permissions.includes(permission),
    );
  }
}
```

**What it does:**

- More granular than roles
- Checks specific permissions like `products:create`, `orders:read:own`
- Supports wildcard: `products:*` grants all product permissions

#### Guard Execution Order

```
Request
    │
    ▼
┌──────────────────┐
│  ThrottlerGuard  │ ← Rate limiting (global)
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│   JwtAuthGuard   │ ← Authenticate user (global)
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│    RolesGuard    │ ← Check role (global)
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│PermissionsGuard  │ ← Check permissions (global)
└────────┬─────────┘
         │
         ▼
    Controller
```

---

### Decorators

**Decorators** are special functions that add metadata to classes, methods, or parameters. NestJS uses this metadata to configure behavior.

#### Custom Decorators We Created

##### 1. @Public()

**File:** `auth/decorators/public.decorator.ts`

```typescript
export const IS_PUBLIC_KEY = 'isPublic';
export const Public = () => SetMetadata(IS_PUBLIC_KEY, true);
```

**Usage:**

```typescript
@Public()  // ← This route skips JWT authentication
@Post('login')
async login(@Body() loginDto: LoginDto) { ... }
```

**How it works:**

1. `@Public()` sets metadata `isPublic: true` on the route
2. `JwtAuthGuard` reads this metadata
3. If `isPublic` is true, guard returns true without checking JWT

##### 2. @Roles()

**File:** `auth/decorators/roles.decorator.ts`

```typescript
export const ROLES_KEY = 'roles';
export const Roles = (...roles: UserRole[]) => SetMetadata(ROLES_KEY, roles);
```

**Usage:**

```typescript
@Roles(UserRole.ADMIN, UserRole.RESTAURANT)  // ← Only admin or restaurant
@Post('products')
async createProduct() { ... }
```

##### 3. @Permissions()

**File:** `auth/decorators/permissions.decorator.ts`

```typescript
export const PERMISSIONS_KEY = 'permissions';
export const Permissions = (...permissions: string[]) =>
  SetMetadata(PERMISSIONS_KEY, permissions);
```

**Usage:**

```typescript
@Permissions('products:create', 'products:update')
@Post('products')
async createProduct() { ... }
```

##### 4. @CurrentUser()

**File:** `auth/decorators/current-user.decorator.ts`

```typescript
export const CurrentUser = createParamDecorator(
  (data: string | undefined, ctx: ExecutionContext) => {
    const request = ctx.switchToHttp().getRequest();
    const user = request.user;
    return data ? user?.[data] : user;
  },
);
```

**Usage:**

```typescript
@Get('profile')
async getProfile(@CurrentUser() user) {
  // user = { id, email, role, permissions }
  return user;
}

@Get('my-email')
async getEmail(@CurrentUser('email') email: string) {
  // email = "user@example.com"
  return { email };
}
```

---

### Permissions System

#### Why Permissions Over Just Roles?

**Roles are coarse-grained:**

```
ADMIN → Can do everything
USER  → Can do limited things
```

**Permissions are fine-grained:**

```
ADMIN with restricted access:
  - ✅ users:read:all
  - ✅ users:update:all
  - ❌ users:delete        ← Cannot delete users
  - ❌ users:manage:roles  ← Cannot change roles
```

This allows creating "Support Admin" who can view/edit users but not delete or change roles.

#### Permission Naming Convention

```
module:action:scope
   │      │      │
   │      │      └── Scope: own, all, assigned, restaurant
   │      └── Action: create, read, update, delete, manage
   └── Module: products, orders, users, etc.
```

**Examples:**
| Permission | Meaning |
|------------|---------|
| `products:read` | Can view products |
| `products:create` | Can create products |
| `products:update:own` | Can update only their own products |
| `products:update:all` | Can update any product |
| `orders:read:assigned` | (Rider) Can see orders assigned to them |
| `orders:read:restaurant` | (Restaurant) Can see their restaurant's orders |

#### How Permissions Are Assigned

```
User
  │
  ├── role: "restaurant"
  │       │
  │       └── Default permissions from RolePermission collection:
  │           - products:read
  │           - products:create
  │           - products:update:own
  │           - ...
  │
  └── permissions: ["orders:read:all"]  ← Additional custom permissions
              │
              └── This user can also read ALL orders (not just their restaurant's)
```

#### Permission Check Flow

```typescript
// In auth.service.ts during login:
const rolePermissions = await this.permissionsService.getPermissionsForRole(
  user.role,
);
const allPermissions = [...new Set([...rolePermissions, ...user.permissions])];
```

This merges:

1. **Role-based permissions** (from database, seeded on startup)
2. **User-specific permissions** (assigned to individual user)

---

## Security Features

### 1. Account Lockout

**Prevents brute-force attacks**

```
Login Attempt 1 → Failed ❌
Login Attempt 2 → Failed ❌
Login Attempt 3 → Failed ❌
Login Attempt 4 → Failed ❌
Login Attempt 5 → Failed ❌ → LOCKED 🔒 (30 minutes)
```

**Configuration:**

- Max attempts: 5
- Window: 15 minutes
- Lockout duration: 30 minutes

### 2. Rate Limiting

**Prevents API abuse**

| Endpoint                | Limit      | Window    |
| ----------------------- | ---------- | --------- |
| `/auth/login`           | 5 requests | 1 minute  |
| `/auth/register`        | 3 requests | 1 minute  |
| `/auth/forgot-password` | 3 requests | 5 minutes |

### 3. Token Blacklisting

When a user logs out, their token is blacklisted:

```typescript
// On logout:
await this.securityService.blacklistToken(
  jti,
  expiresAt,
  userId,
  'User logout',
);

// On every request, JwtStrategy checks:
if (await this.securityService.isTokenBlacklisted(payload.jti)) {
  return null; // Reject request
}
```

### 4. Audit Logging

Every security event is logged:

```typescript
enum AuditAction {
  LOGIN_SUCCESS = 'login_success',
  LOGIN_FAILED = 'login_failed',
  LOGOUT = 'logout',
  PASSWORD_CHANGED = 'password_changed',
  ACCOUNT_LOCKED = 'account_locked',
  // ... more events
}
```

**Stored data:**

- User ID
- Action type
- IP address
- User agent
- Timestamp
- Additional metadata

---

## API Reference

### Auth Endpoints

| Method | Endpoint                    | Auth | Rate Limit | Description                 |
| ------ | --------------------------- | ---- | ---------- | --------------------------- |
| POST   | `/auth/register`            | ❌   | 3/min      | Register new user           |
| POST   | `/auth/verify-email`        | ❌   | -          | Verify email token          |
| POST   | `/auth/resend-verification` | ❌   | 3/5min     | Resend verification         |
| POST   | `/auth/login`               | ❌   | 5/min      | Login                       |
| POST   | `/auth/refresh`             | ❌   | -          | Refresh tokens              |
| POST   | `/auth/logout`              | ✅   | -          | Logout current session      |
| POST   | `/auth/logout-all`          | ✅   | -          | Logout all devices          |
| GET    | `/auth/sessions`            | ✅   | -          | List active sessions        |
| DELETE | `/auth/sessions/:id`        | ✅   | -          | Revoke specific session     |
| POST   | `/auth/forgot-password`     | ❌   | 3/5min     | Request password reset      |
| POST   | `/auth/reset-password`      | ❌   | -          | Reset password with token   |
| POST   | `/auth/change-password`     | ✅   | -          | Change password (logged in) |

### User Endpoints

| Method | Endpoint                 | Auth | Role  | Description              |
| ------ | ------------------------ | ---- | ----- | ------------------------ |
| GET    | `/users/me`              | ✅   | Any   | Get current user profile |
| PATCH  | `/users/me`              | ✅   | Any   | Update own profile       |
| GET    | `/users`                 | ✅   | Admin | List all users           |
| GET    | `/users/:id`             | ✅   | Admin | Get user by ID           |
| PATCH  | `/users/:id`             | ✅   | Admin | Update user              |
| PATCH  | `/users/:id/role`        | ✅   | Admin | Change user role         |
| PATCH  | `/users/:id/unlock`      | ✅   | Admin | Unlock locked account    |
| PATCH  | `/users/:id/permissions` | ✅   | Admin | Update user permissions  |

---

## Database Schema

### User

```typescript
{
  email: string,           // Unique, lowercase
  password: string,        // Hashed with bcrypt
  firstName: string,
  lastName: string,
  phone?: string,
  role: UserRole,          // user, admin, restaurant, rider
  status: UserStatus,      // pending_verification, active, locked, suspended
  emailVerified: boolean,
  permissions: string[],   // Additional permissions beyond role
  failedLoginAttempts: number,
  lockedAt?: Date,
  lockReason?: string,
  lastLoginAt?: Date,
  lastLoginIp?: string,
  createdAt: Date,
  updatedAt: Date
}
```

### Session

```typescript
{
  userId: ObjectId,
  refreshToken: string,    // Hashed
  jti: string,             // JWT ID for blacklisting
  userAgent: string,
  ip: string,
  lastActive: Date,
  expiresAt: Date,         // TTL index for auto-cleanup
  revoked: boolean,
  revokedAt?: Date,
  revokedReason?: string
}
```

### Permission

```typescript
{
  name: string,            // 'products:create'
  description: string,
  module: string,          // 'products'
  action: string,          // 'create'
  scope?: string,          // 'own', 'all'
  isActive: boolean
}
```

### RolePermission

```typescript
{
  role: UserRole,
  permissions: string[],   // List of permission names
  isActive: boolean
}
```

### AuditLog

```typescript
{
  userId?: ObjectId,
  action: AuditAction,
  ip: string,
  userAgent?: string,
  metadata?: object,
  targetUserId?: ObjectId, // For admin actions on other users
  suspicious: boolean,
  createdAt: Date          // TTL: 90 days
}
```

---

## Further Reading

- [NestJS Guards](https://docs.nestjs.com/guards)
- [NestJS Custom Decorators](https://docs.nestjs.com/custom-decorators)
- [Passport JWT Strategy](http://www.passportjs.org/packages/passport-jwt/)
- [JWT.io - Debug Tokens](https://jwt.io/)
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
