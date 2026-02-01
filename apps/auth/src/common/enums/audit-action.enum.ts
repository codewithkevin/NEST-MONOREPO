export enum AuditAction {
  // Auth events
  LOGIN_SUCCESS = 'login_success',
  LOGIN_FAILED = 'login_failed',
  LOGOUT = 'logout',
  LOGOUT_ALL = 'logout_all',

  // Registration events
  REGISTER = 'register',
  EMAIL_VERIFIED = 'email_verified',
  VERIFICATION_RESENT = 'verification_resent',

  // Password events
  PASSWORD_CHANGED = 'password_changed',
  PASSWORD_RESET_REQUESTED = 'password_reset_requested',
  PASSWORD_RESET_COMPLETED = 'password_reset_completed',

  // Account events
  ACCOUNT_LOCKED = 'account_locked',
  ACCOUNT_UNLOCKED = 'account_unlocked',
  ACCOUNT_SUSPENDED = 'account_suspended',
  ACCOUNT_REACTIVATED = 'account_reactivated',

  // Session events
  SESSION_REVOKED = 'session_revoked',
  TOKEN_REFRESHED = 'token_refreshed',

  // Admin events
  ROLE_CHANGED = 'role_changed',
  PERMISSIONS_UPDATED = 'permissions_updated',
  USER_CREATED_BY_ADMIN = 'user_created_by_admin',
  USER_UPDATED_BY_ADMIN = 'user_updated_by_admin',
}
