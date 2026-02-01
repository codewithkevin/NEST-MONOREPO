import { Module } from '@nestjs/common';
import { MongooseModule } from '@nestjs/mongoose';
import { SecurityService } from './security.service';
import { AuditLog, AuditLogSchema } from './entities/audit-log.entity';
import {
  LoginAttempt,
  LoginAttemptSchema,
} from './entities/login-attempt.entity';
import {
  TokenBlacklist,
  TokenBlacklistSchema,
} from './entities/token-blacklist.entity';

@Module({
  imports: [
    MongooseModule.forFeature([
      { name: AuditLog.name, schema: AuditLogSchema },
      { name: LoginAttempt.name, schema: LoginAttemptSchema },
      { name: TokenBlacklist.name, schema: TokenBlacklistSchema },
    ]),
  ],
  providers: [SecurityService],
  exports: [SecurityService],
})
export class SecurityModule {}
