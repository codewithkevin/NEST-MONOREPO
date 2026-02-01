import {
  Injectable,
  UnauthorizedException,
  BadRequestException,
  NotFoundException,
} from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model, Types, HydratedDocument } from 'mongoose';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import * as bcrypt from 'bcrypt';
import { v4 as uuidv4 } from 'uuid';
import { Session } from './entities/session.entity';
import { EmailVerification } from './entities/email-verification.entity';
import { PasswordReset } from './entities/password-reset.entity';
import { UsersService } from '../users/users.service';
import { SecurityService } from '../security/security.service';
import { PermissionsService } from '../permissions/permissions.service';
import {
  RegisterDto,
  LoginDto,
  VerifyEmailDto,
  ForgotPasswordDto,
  ResetPasswordDto,
  ChangePasswordDto,
} from './dto';
import { UserRole, UserStatus, AuditAction } from '../common/enums';

export interface JwtPayload {
  sub: string;
  email: string;
  role: UserRole;
  jti: string;
}

export interface AuthResponse {
  accessToken: string;
  refreshToken: string;
  user: {
    id: string;
    email: string;
    firstName: string;
    lastName: string;
    role: UserRole;
    permissions: string[];
  };
}

@Injectable()
export class AuthService {
  private readonly jwtSecret: string;
  private readonly jwtRefreshSecret: string;
  private readonly accessTokenExpiry = '15m';
  private readonly refreshTokenExpiry = '7d';

  constructor(
    @InjectModel(Session.name) private sessionModel: Model<Session>,
    @InjectModel(EmailVerification.name)
    private emailVerificationModel: Model<EmailVerification>,
    @InjectModel(PasswordReset.name)
    private passwordResetModel: Model<PasswordReset>,
    private jwtService: JwtService,
    private configService: ConfigService,
    private usersService: UsersService,
    private securityService: SecurityService,
    private permissionsService: PermissionsService,
  ) {
    this.jwtSecret =
      this.configService.get<string>('JWT_SECRET') || 'your-secret-key';
    this.jwtRefreshSecret =
      this.configService.get<string>('JWT_REFRESH_SECRET') ||
      'your-refresh-secret';
  }

  // ========== Registration ==========

  async register(
    registerDto: RegisterDto,
    ip: string,
    userAgent?: string,
  ): Promise<{ message: string }> {
    // Create user (unverified)
    const user = await this.usersService.create({
      ...registerDto,
      role: registerDto.role || UserRole.USER,
    });

    // Create email verification token
    const verificationToken = uuidv4();
    const hashedToken = await bcrypt.hash(verificationToken, 10);

    await this.emailVerificationModel.create({
      userId: user._id,
      token: hashedToken,
      expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000), // 24 hours
    });

    // Log audit event
    await this.securityService.logAuditEvent(
      AuditAction.REGISTER,
      ip,
      userAgent,
      user._id,
      { email: user.email },
    );

    // TODO: Send verification email
    console.log(
      `[EMAIL] Verification token for ${user.email}: ${verificationToken}`,
    );

    return {
      message:
        'Registration successful. Please check your email to verify your account.',
    };
  }

  async verifyEmail(
    verifyDto: VerifyEmailDto,
    ip: string,
    userAgent?: string,
  ): Promise<{ message: string }> {
    // Find all pending verifications
    const verifications = await this.emailVerificationModel
      .find({ used: false, expiresAt: { $gt: new Date() } })
      .exec();

    let matchedVerification: HydratedDocument<EmailVerification> | undefined;
    let matchedUserId: Types.ObjectId | undefined;

    // Check each verification token
    for (const verification of verifications) {
      const isMatch = await bcrypt.compare(verifyDto.token, verification.token);
      if (isMatch) {
        matchedVerification = verification;
        matchedUserId = verification.userId;
        break;
      }
    }

    if (!matchedVerification || !matchedUserId) {
      throw new BadRequestException('Invalid or expired verification token');
    }

    // Verify user's email
    await this.usersService.verifyEmail(matchedUserId.toString());

    // Mark token as used
    matchedVerification.used = true;
    matchedVerification.usedAt = new Date();
    await matchedVerification.save();

    // Log audit event
    await this.securityService.logAuditEvent(
      AuditAction.EMAIL_VERIFIED,
      ip,
      userAgent,
      matchedUserId,
    );

    return { message: 'Email verified successfully. You can now login.' };
  }

  async resendVerification(
    email: string,
    ip: string,
    userAgent?: string,
  ): Promise<{ message: string }> {
    const user = await this.usersService.findByEmail(email);

    if (!user) {
      // Don't reveal if user exists
      return {
        message:
          'If your email is registered, you will receive a verification email.',
      };
    }

    if (user.emailVerified) {
      return { message: 'Email is already verified.' };
    }

    // Invalidate old tokens
    await this.emailVerificationModel.updateMany(
      { userId: user._id },
      { used: true },
    );

    // Create new token
    const verificationToken = uuidv4();
    const hashedToken = await bcrypt.hash(verificationToken, 10);

    await this.emailVerificationModel.create({
      userId: user._id,
      token: hashedToken,
      expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000),
    });

    // Log audit event
    await this.securityService.logAuditEvent(
      AuditAction.VERIFICATION_RESENT,
      ip,
      userAgent,
      user._id,
    );

    // TODO: Send verification email
    console.log(
      `[EMAIL] New verification token for ${user.email}: ${verificationToken}`,
    );

    return {
      message:
        'If your email is registered, you will receive a verification email.',
    };
  }

  // ========== Login ==========

  async login(
    loginDto: LoginDto,
    ip: string,
    userAgent?: string,
  ): Promise<AuthResponse> {
    const { email, password } = loginDto;

    // Check if account is locked (based on failed attempts)
    const lockStatus = await this.securityService.isAccountLocked(email);
    if (lockStatus.locked) {
      await this.securityService.recordLoginAttempt(
        email,
        ip,
        false,
        userAgent,
        'Account locked',
      );
      throw new UnauthorizedException(
        `Account is locked. Try again after ${lockStatus.unlockTime?.toISOString()}`,
      );
    }

    // Find user
    const user = await this.usersService.findByEmail(email);

    if (!user) {
      await this.securityService.recordLoginAttempt(
        email,
        ip,
        false,
        userAgent,
        'User not found',
      );
      await this.securityService.logAuditEvent(
        AuditAction.LOGIN_FAILED,
        ip,
        userAgent,
        undefined,
        { email, reason: 'User not found' },
      );
      throw new UnauthorizedException('Invalid credentials');
    }

    // Check email verification
    if (!user.emailVerified) {
      await this.securityService.recordLoginAttempt(
        email,
        ip,
        false,
        userAgent,
        'Email not verified',
      );
      throw new UnauthorizedException(
        'Please verify your email before logging in',
      );
    }

    // Check account status
    if (user.status === UserStatus.LOCKED) {
      await this.securityService.recordLoginAttempt(
        email,
        ip,
        false,
        userAgent,
        'Account locked',
      );
      throw new UnauthorizedException(
        'Your account has been locked. Please contact support.',
      );
    }

    if (user.status === UserStatus.SUSPENDED) {
      await this.securityService.recordLoginAttempt(
        email,
        ip,
        false,
        userAgent,
        'Account suspended',
      );
      throw new UnauthorizedException('Your account has been suspended.');
    }

    // Validate password
    const isPasswordValid = await this.usersService.validatePassword(
      user,
      password,
    );

    if (!isPasswordValid) {
      await this.securityService.recordLoginAttempt(
        email,
        ip,
        false,
        userAgent,
        'Invalid password',
      );
      const failedAttempts = await this.usersService.incrementFailedAttempts(
        user._id.toString(),
      );

      // Check if we should lock the account
      const MAX_FAILED_ATTEMPTS = 5;
      if (failedAttempts >= MAX_FAILED_ATTEMPTS) {
        await this.usersService.lockAccount(
          user._id.toString(),
          'Too many failed login attempts',
        );
        await this.securityService.logAuditEvent(
          AuditAction.ACCOUNT_LOCKED,
          ip,
          userAgent,
          user._id,
          { reason: 'Failed attempts' },
        );
      }

      await this.securityService.logAuditEvent(
        AuditAction.LOGIN_FAILED,
        ip,
        userAgent,
        user._id,
        { reason: 'Invalid password' },
      );
      throw new UnauthorizedException('Invalid credentials');
    }

    // Success - clear failed attempts and update login info
    await this.securityService.clearLoginAttempts(email);
    await this.securityService.recordLoginAttempt(email, ip, true, userAgent);
    await this.usersService.updateLoginInfo(user._id.toString(), ip);

    // Get user permissions
    const rolePermissions = await this.permissionsService.getPermissionsForRole(
      user.role,
    );
    const allPermissions = [
      ...new Set([...rolePermissions, ...user.permissions]),
    ];

    // Generate tokens and create session
    const tokens = await this.createSession(
      user._id,
      user.email,
      user.role,
      ip,
      userAgent,
    );

    // Log successful login
    await this.securityService.logAuditEvent(
      AuditAction.LOGIN_SUCCESS,
      ip,
      userAgent,
      user._id,
    );

    return {
      ...tokens,
      user: {
        id: user._id.toString(),
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        role: user.role,
        permissions: allPermissions,
      },
    };
  }

  // ========== Token Management ==========

  private async createSession(
    userId: Types.ObjectId,
    email: string,
    role: UserRole,
    ip: string,
    userAgent?: string,
  ): Promise<{ accessToken: string; refreshToken: string }> {
    const jti = uuidv4();
    const refreshJti = uuidv4();

    const accessToken = await this.jwtService.signAsync(
      { sub: userId.toString(), email, role, jti },
      { secret: this.jwtSecret, expiresIn: this.accessTokenExpiry },
    );

    const refreshToken = await this.jwtService.signAsync(
      { sub: userId.toString(), email, role, jti: refreshJti },
      { secret: this.jwtRefreshSecret, expiresIn: this.refreshTokenExpiry },
    );

    const hashedRefreshToken = await bcrypt.hash(refreshToken, 10);

    // Store session
    await this.sessionModel.create({
      userId,
      refreshToken: hashedRefreshToken,
      jti: refreshJti,
      ip,
      userAgent,
      expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // 7 days
    });

    return { accessToken, refreshToken };
  }

  async refreshTokens(
    refreshToken: string,
    ip: string,
    userAgent?: string,
  ): Promise<AuthResponse> {
    // Verify refresh token
    let payload: JwtPayload;
    try {
      payload = await this.jwtService.verifyAsync<JwtPayload>(refreshToken, {
        secret: this.jwtRefreshSecret,
      });
    } catch {
      throw new UnauthorizedException('Invalid refresh token');
    }

    // Check if token is blacklisted
    if (await this.securityService.isTokenBlacklisted(payload.jti)) {
      throw new UnauthorizedException('Token has been revoked');
    }

    // Find session
    const session = await this.sessionModel
      .findOne({
        jti: payload.jti,
        revoked: false,
      })
      .exec();

    if (!session) {
      throw new UnauthorizedException('Session not found or revoked');
    }

    // Verify refresh token matches stored hash
    const isValid = await bcrypt.compare(refreshToken, session.refreshToken);
    if (!isValid) {
      throw new UnauthorizedException('Invalid refresh token');
    }

    // Get user
    const user = await this.usersService.findById(payload.sub);
    if (!user || user.status !== UserStatus.ACTIVE) {
      throw new UnauthorizedException('User not found or inactive');
    }

    // Revoke old session
    session.revoked = true;
    session.revokedAt = new Date();
    session.revokedReason = 'Token refreshed';
    await session.save();

    // Blacklist old token
    await this.securityService.blacklistToken(
      payload.jti,
      session.expiresAt,
      user._id,
      'Token refreshed',
    );

    // Get permissions
    const rolePermissions = await this.permissionsService.getPermissionsForRole(
      user.role,
    );
    const allPermissions = [
      ...new Set([...rolePermissions, ...user.permissions]),
    ];

    // Create new session
    const tokens = await this.createSession(
      user._id,
      user.email,
      user.role,
      ip,
      userAgent,
    );

    // Log audit event
    await this.securityService.logAuditEvent(
      AuditAction.TOKEN_REFRESHED,
      ip,
      userAgent,
      user._id,
    );

    return {
      ...tokens,
      user: {
        id: user._id.toString(),
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        role: user.role,
        permissions: allPermissions,
      },
    };
  }

  // ========== Logout ==========

  async logout(
    userId: string,
    jti: string,
    ip: string,
    userAgent?: string,
  ): Promise<void> {
    // Find and revoke session
    const session = await this.sessionModel
      .findOne({ jti, userId: new Types.ObjectId(userId) })
      .exec();

    if (session) {
      session.revoked = true;
      session.revokedAt = new Date();
      session.revokedReason = 'User logout';
      await session.save();

      // Blacklist token
      await this.securityService.blacklistToken(
        jti,
        session.expiresAt,
        new Types.ObjectId(userId),
        'User logout',
      );
    }

    // Log audit event
    await this.securityService.logAuditEvent(
      AuditAction.LOGOUT,
      ip,
      userAgent,
      new Types.ObjectId(userId),
    );
  }

  async logoutAll(
    userId: string,
    ip: string,
    userAgent?: string,
  ): Promise<void> {
    // Revoke all sessions
    const sessions = await this.sessionModel
      .find({
        userId: new Types.ObjectId(userId),
        revoked: false,
      })
      .exec();

    for (const session of sessions) {
      session.revoked = true;
      session.revokedAt = new Date();
      session.revokedReason = 'Logout all devices';
      await session.save();

      // Blacklist token
      await this.securityService.blacklistToken(
        session.jti,
        session.expiresAt,
        new Types.ObjectId(userId),
        'Logout all',
      );
    }

    // Log audit event
    await this.securityService.logAuditEvent(
      AuditAction.LOGOUT_ALL,
      ip,
      userAgent,
      new Types.ObjectId(userId),
      { sessionCount: sessions.length },
    );
  }

  // ========== Session Management ==========

  async getActiveSessions(userId: string) {
    const sessions = await this.sessionModel
      .find({
        userId: new Types.ObjectId(userId),
        revoked: false,
        expiresAt: { $gt: new Date() },
      })
      .select('-refreshToken')
      .sort({ lastActive: -1 })
      .exec();

    return sessions.map((s) => ({
      id: s._id.toString(),
      ip: s.ip,
      userAgent: s.userAgent,
      lastActive: s.lastActive,
      createdAt: s.createdAt,
    }));
  }

  async revokeSession(
    userId: string,
    sessionId: string,
    ip: string,
    userAgent?: string,
  ): Promise<void> {
    const session = await this.sessionModel
      .findOne({
        _id: new Types.ObjectId(sessionId),
        userId: new Types.ObjectId(userId),
      })
      .exec();

    if (!session) {
      throw new NotFoundException('Session not found');
    }

    session.revoked = true;
    session.revokedAt = new Date();
    session.revokedReason = 'Manually revoked';
    await session.save();

    // Blacklist the token
    await this.securityService.blacklistToken(
      session.jti,
      session.expiresAt,
      new Types.ObjectId(userId),
      'Manually revoked',
    );

    // Log audit event
    await this.securityService.logAuditEvent(
      AuditAction.SESSION_REVOKED,
      ip,
      userAgent,
      new Types.ObjectId(userId),
      { sessionId },
    );
  }

  // ========== Password Reset ==========

  async forgotPassword(
    forgotPasswordDto: ForgotPasswordDto,
    ip: string,
    userAgent?: string,
  ): Promise<{ message: string }> {
    const user = await this.usersService.findByEmail(forgotPasswordDto.email);

    // Always return success to prevent email enumeration
    const successMessage = {
      message:
        'If your email is registered, you will receive a password reset link.',
    };

    if (!user) {
      return successMessage;
    }

    // Invalidate old reset tokens
    await this.passwordResetModel.updateMany(
      { userId: user._id },
      { used: true },
    );

    // Create reset token
    const resetToken = uuidv4();
    const hashedToken = await bcrypt.hash(resetToken, 10);

    await this.passwordResetModel.create({
      userId: user._id,
      token: hashedToken,
      expiresAt: new Date(Date.now() + 60 * 60 * 1000), // 1 hour
      ip,
    });

    // Log audit event
    await this.securityService.logAuditEvent(
      AuditAction.PASSWORD_RESET_REQUESTED,
      ip,
      userAgent,
      user._id,
    );

    // TODO: Send reset email
    console.log(
      `[EMAIL] Password reset token for ${user.email}: ${resetToken}`,
    );

    return successMessage;
  }

  async resetPassword(
    resetPasswordDto: ResetPasswordDto,
    ip: string,
    userAgent?: string,
  ): Promise<{ message: string }> {
    // Find valid reset tokens
    const resetTokens = await this.passwordResetModel
      .find({ used: false, expiresAt: { $gt: new Date() } })
      .exec();

    let matchedToken: HydratedDocument<PasswordReset> | undefined;
    let matchedUserId: Types.ObjectId | undefined;

    for (const token of resetTokens) {
      const isMatch = await bcrypt.compare(resetPasswordDto.token, token.token);
      if (isMatch) {
        matchedToken = token;
        matchedUserId = token.userId;
        break;
      }
    }

    if (!matchedToken || !matchedUserId) {
      throw new BadRequestException('Invalid or expired reset token');
    }

    // Update password
    await this.usersService.changePassword(
      matchedUserId.toString(),
      resetPasswordDto.newPassword,
    );

    // Mark token as used
    matchedToken.used = true;
    matchedToken.usedAt = new Date();
    await matchedToken.save();

    // Revoke all sessions (security measure)
    await this.logoutAll(matchedUserId.toString(), ip, userAgent);

    // Log audit event
    await this.securityService.logAuditEvent(
      AuditAction.PASSWORD_RESET_COMPLETED,
      ip,
      userAgent,
      matchedUserId,
    );

    return {
      message:
        'Password reset successful. Please login with your new password.',
    };
  }

  async changePassword(
    userId: string,
    changePasswordDto: ChangePasswordDto,
    ip: string,
    userAgent?: string,
  ): Promise<{ message: string }> {
    const user = await this.usersService.findById(userId);

    if (!user) {
      throw new NotFoundException('User not found');
    }

    // Verify current password
    const isValid = await this.usersService.validatePassword(
      user,
      changePasswordDto.currentPassword,
    );
    if (!isValid) {
      throw new BadRequestException('Current password is incorrect');
    }

    // Update password
    await this.usersService.changePassword(
      userId,
      changePasswordDto.newPassword,
    );

    // Revoke all other sessions
    const sessions = await this.sessionModel
      .find({
        userId: new Types.ObjectId(userId),
        revoked: false,
      })
      .exec();

    for (const session of sessions) {
      session.revoked = true;
      session.revokedAt = new Date();
      session.revokedReason = 'Password changed';
      await session.save();
    }

    // Log audit event
    await this.securityService.logAuditEvent(
      AuditAction.PASSWORD_CHANGED,
      ip,
      userAgent,
      new Types.ObjectId(userId),
    );

    return { message: 'Password changed successfully. Please login again.' };
  }

  // ========== Token Validation ==========

  async validateUser(userId: string): Promise<{
    id: string;
    email: string;
    role: UserRole;
    permissions: string[];
  } | null> {
    const user = await this.usersService.findById(userId);

    if (!user || user.status !== UserStatus.ACTIVE) {
      return null;
    }

    const rolePermissions = await this.permissionsService.getPermissionsForRole(
      user.role,
    );
    const allPermissions = [
      ...new Set([...rolePermissions, ...user.permissions]),
    ];

    return {
      id: user._id.toString(),
      email: user.email,
      role: user.role,
      permissions: allPermissions,
    };
  }
}
