import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { HydratedDocument, Types } from 'mongoose';

export type PermissionDocument = HydratedDocument<Permission>;

@Schema({ timestamps: true })
export class Permission {
  _id: Types.ObjectId;

  @Prop({ required: true, unique: true })
  name: string; // e.g., 'products:create', 'orders:read:own'

  @Prop({ required: true })
  description: string;

  @Prop({ required: true, index: true })
  module: string; // e.g., 'products', 'orders', 'users'

  @Prop({ required: true })
  action: string; // e.g., 'create', 'read', 'update', 'delete'

  @Prop()
  scope?: string; // e.g., 'own', 'restaurant', 'all'

  @Prop({ default: true })
  isActive: boolean;

  @Prop()
  createdAt: Date;

  @Prop()
  updatedAt: Date;
}

export const PermissionSchema = SchemaFactory.createForClass(Permission);

// Indexes
PermissionSchema.index({ module: 1, action: 1 });
