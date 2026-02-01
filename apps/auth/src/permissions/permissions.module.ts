import { Module } from '@nestjs/common';
import { MongooseModule } from '@nestjs/mongoose';
import { PermissionsService } from './permissions.service';
import { Permission, PermissionSchema } from './entities/permission.entity';
import {
  RolePermission,
  RolePermissionSchema,
} from './entities/role-permission.entity';

@Module({
  imports: [
    MongooseModule.forFeature([
      { name: Permission.name, schema: PermissionSchema },
      { name: RolePermission.name, schema: RolePermissionSchema },
    ]),
  ],
  providers: [PermissionsService],
  exports: [PermissionsService],
})
export class PermissionsModule {}
