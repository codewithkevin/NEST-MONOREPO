import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { HydratedDocument, Types } from 'mongoose';

export type TokenBlacklistDocument = HydratedDocument<TokenBlacklist>;

@Schema({ timestamps: true })
export class TokenBlacklist {
  _id: Types.ObjectId;

  @Prop({ required: true, unique: true, index: true })
  jti: string; // JWT ID

  @Prop({ type: Types.ObjectId, ref: 'User' })
  userId?: Types.ObjectId;

  @Prop({ required: true })
  expiresAt: Date;

  @Prop()
  reason?: string;

  @Prop()
  createdAt: Date;
}

export const TokenBlacklistSchema =
  SchemaFactory.createForClass(TokenBlacklist);

// TTL index - auto delete when token would have expired anyway
TokenBlacklistSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });
