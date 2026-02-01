import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { HydratedDocument, Types } from 'mongoose';
import { UserRole } from '../../common/enums';

export type RolePermissionDocument = HydratedDocument<RolePermission>;

@Schema({ timestamps: true })
export class RolePermission {
  _id: Types.ObjectId;

  @Prop({ type: String, enum: UserRole, required: true, unique: true })
  role: UserRole;

  @Prop({ type: [String], default: [] })
  permissions: string[]; // Permission names

  @Prop()
  description?: string;

  @Prop({ default: true })
  isActive: boolean;

  @Prop()
  createdAt: Date;

  @Prop()
  updatedAt: Date;
}

export const RolePermissionSchema =
  SchemaFactory.createForClass(RolePermission);
