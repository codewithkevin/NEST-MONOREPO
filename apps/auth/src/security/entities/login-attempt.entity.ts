import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { HydratedDocument, Types } from 'mongoose';

export type LoginAttemptDocument = HydratedDocument<LoginAttempt>;

@Schema({ timestamps: true })
export class LoginAttempt {
  _id: Types.ObjectId;

  @Prop({ required: true, lowercase: true, index: true })
  email: string;

  @Prop({ required: true, index: true })
  ip: string;

  @Prop({ default: false })
  success: boolean;

  @Prop()
  userAgent?: string;

  @Prop()
  failureReason?: string;

  @Prop()
  createdAt: Date;
}

export const LoginAttemptSchema = SchemaFactory.createForClass(LoginAttempt);

// Compound index for lockout checking
LoginAttemptSchema.index({ email: 1, createdAt: -1 });
LoginAttemptSchema.index({ ip: 1, createdAt: -1 });

// TTL index - auto delete after 1 hour
LoginAttemptSchema.index({ createdAt: 1 }, { expireAfterSeconds: 3600 });
