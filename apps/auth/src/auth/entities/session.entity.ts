import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { HydratedDocument, Types } from 'mongoose';

export type SessionDocument = HydratedDocument<Session>;

@Schema({ timestamps: true })
export class Session {
  _id: Types.ObjectId;

  @Prop({ type: Types.ObjectId, ref: 'User', required: true, index: true })
  userId: Types.ObjectId;

  @Prop({ required: true })
  refreshToken: string; // Hashed

  @Prop({ required: true })
  jti: string; // JWT ID for blacklisting

  @Prop()
  userAgent: string;

  @Prop()
  ip: string;

  @Prop()
  deviceInfo?: string;

  @Prop({ default: Date.now })
  lastActive: Date;

  @Prop({ required: true })
  expiresAt: Date;

  @Prop({ default: false })
  revoked: boolean;

  @Prop()
  revokedAt?: Date;

  @Prop()
  revokedReason?: string;

  @Prop()
  createdAt: Date;
}

export const SessionSchema = SchemaFactory.createForClass(Session);

// Indexes
SessionSchema.index({ userId: 1 });
SessionSchema.index({ jti: 1 });
SessionSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 }); // TTL index
