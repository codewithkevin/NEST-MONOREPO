import { Injectable } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model, Types } from 'mongoose';
import { AuditLog } from './entities/audit-log.entity';
import { LoginAttempt } from './entities/login-attempt.entity';
import { TokenBlacklist } from './entities/token-blacklist.entity';
import { AuditAction } from '../common/enums';

@Injectable()
export class SecurityService {
  private readonly MAX_FAILED_ATTEMPTS = 5;
  private readonly LOCKOUT_DURATION_MINUTES = 30;
  private readonly ATTEMPT_WINDOW_MINUTES = 15;

  constructor(
    @InjectModel(AuditLog.name) private auditLogModel: Model<AuditLog>,
    @InjectModel(LoginAttempt.name)
    private loginAttemptModel: Model<LoginAttempt>,
    @InjectModel(TokenBlacklist.name)
    private tokenBlacklistModel: Model<TokenBlacklist>,
  ) {}

  // ========== Audit Logging ==========

  async logAuditEvent(
    action: AuditAction,
    ip: string,
    userAgent?: string,
    userId?: Types.ObjectId,
    metadata?: Record<string, unknown>,
    targetUserId?: Types.ObjectId,
    sessionId?: string,
    suspicious?: boolean,
  ): Promise<AuditLog> {
    const log = new this.auditLogModel({
      action,
      ip,
      userAgent,
      userId,
      metadata,
      targetUserId,
      sessionId,
      suspicious: suspicious || false,
    });
    return log.save();
  }

  async getAuditLogs(
    userId?: string,
    action?: AuditAction,
    page = 1,
    limit = 20,
  ) {
    const query: Record<string, unknown> = {};
    if (userId) query.userId = new Types.ObjectId(userId);
    if (action) query.action = action;

    const [logs, total] = await Promise.all([
      this.auditLogModel
        .find(query)
        .sort({ createdAt: -1 })
        .skip((page - 1) * limit)
        .limit(limit)
        .exec(),
      this.auditLogModel.countDocuments(query).exec(),
    ]);

    return { logs, total, page, limit };
  }

  async getUserLoginHistory(userId: string, limit = 10) {
    return this.auditLogModel
      .find({
        userId: new Types.ObjectId(userId),
        action: { $in: [AuditAction.LOGIN_SUCCESS, AuditAction.LOGIN_FAILED] },
      })
      .sort({ createdAt: -1 })
      .limit(limit)
      .exec();
  }

  // ========== Login Attempts & Lockout ==========

  async recordLoginAttempt(
    email: string,
    ip: string,
    success: boolean,
    userAgent?: string,
    failureReason?: string,
  ): Promise<LoginAttempt> {
    const attempt = new this.loginAttemptModel({
      email: email.toLowerCase(),
      ip,
      success,
      userAgent,
      failureReason,
    });
    return attempt.save();
  }

  async getRecentFailedAttempts(email: string): Promise<number> {
    const windowStart = new Date();
    windowStart.setMinutes(
      windowStart.getMinutes() - this.ATTEMPT_WINDOW_MINUTES,
    );

    return this.loginAttemptModel
      .countDocuments({
        email: email.toLowerCase(),
        success: false,
        createdAt: { $gte: windowStart },
      })
      .exec();
  }

  async isAccountLocked(
    email: string,
  ): Promise<{ locked: boolean; unlockTime?: Date }> {
    const failedAttempts = await this.getRecentFailedAttempts(email);

    if (failedAttempts >= this.MAX_FAILED_ATTEMPTS) {
      const lastAttempt = await this.loginAttemptModel
        .findOne({ email: email.toLowerCase(), success: false })
        .sort({ createdAt: -1 })
        .exec();

      if (lastAttempt) {
        const lockExpiry = new Date(lastAttempt.createdAt);
        lockExpiry.setMinutes(
          lockExpiry.getMinutes() + this.LOCKOUT_DURATION_MINUTES,
        );

        if (lockExpiry > new Date()) {
          return { locked: true, unlockTime: lockExpiry };
        }
      }
    }

    return { locked: false };
  }

  async clearLoginAttempts(email: string): Promise<void> {
    await this.loginAttemptModel
      .deleteMany({ email: email.toLowerCase() })
      .exec();
  }

  // ========== Token Blacklisting ==========

  async blacklistToken(
    jti: string,
    expiresAt: Date,
    userId?: Types.ObjectId,
    reason?: string,
  ): Promise<TokenBlacklist> {
    const blacklistEntry = new this.tokenBlacklistModel({
      jti,
      expiresAt,
      userId,
      reason,
    });
    return blacklistEntry.save();
  }

  async isTokenBlacklisted(jti: string): Promise<boolean> {
    const entry = await this.tokenBlacklistModel.findOne({ jti }).exec();
    return !!entry;
  }

  async blacklistAllUserTokens(
    userId: Types.ObjectId,
    reason?: string,
  ): Promise<void> {
    // This is called when user logs out of all sessions
    // The actual tokens are tracked in sessions, this is just for additional safety
    await this.logAuditEvent(
      AuditAction.LOGOUT_ALL,
      'system',
      undefined,
      userId,
      { reason },
    );
  }
}
