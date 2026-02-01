import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { HydratedDocument, Types } from 'mongoose';

export type PasswordResetDocument = HydratedDocument<PasswordReset>;

@Schema({ timestamps: true })
export class PasswordReset {
  _id: Types.ObjectId;

  @Prop({ type: Types.ObjectId, ref: 'User', required: true, index: true })
  userId: Types.ObjectId;

  @Prop({ required: true })
  token: string; // Hashed

  @Prop({ required: true })
  expiresAt: Date;

  @Prop({ default: false })
  used: boolean;

  @Prop()
  usedAt?: Date;

  @Prop()
  ip?: string;

  @Prop()
  createdAt: Date;
}

export const PasswordResetSchema = SchemaFactory.createForClass(PasswordReset);

// TTL index - auto delete after 1 hour
PasswordResetSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });
