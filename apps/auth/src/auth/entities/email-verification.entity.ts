import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { HydratedDocument, Types } from 'mongoose';

export type EmailVerificationDocument = HydratedDocument<EmailVerification>;

@Schema({ timestamps: true })
export class EmailVerification {
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
  createdAt: Date;
}

export const EmailVerificationSchema =
  SchemaFactory.createForClass(EmailVerification);

// TTL index - auto delete after 24 hours
EmailVerificationSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });
