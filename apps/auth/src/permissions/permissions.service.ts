import { Injectable, OnModuleInit } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { Permission } from './entities/permission.entity';
import { RolePermission } from './entities/role-permission.entity';
import { UserRole } from '../common/enums';

// Default permissions for the system
const DEFAULT_PERMISSIONS = [
  // Profile
  {
    name: 'profile:read',
    description: 'View own profile',
    module: 'profile',
    action: 'read',
    scope: 'own',
  },
  {
    name: 'profile:update',
    description: 'Update own profile',
    module: 'profile',
    action: 'update',
    scope: 'own',
  },

  // Orders
  {
    name: 'orders:create',
    description: 'Create orders',
    module: 'orders',
    action: 'create',
  },
  {
    name: 'orders:read:own',
    description: 'View own orders',
    module: 'orders',
    action: 'read',
    scope: 'own',
  },
  {
    name: 'orders:read:assigned',
    description: 'View assigned orders',
    module: 'orders',
    action: 'read',
    scope: 'assigned',
  },
  {
    name: 'orders:read:restaurant',
    description: 'View restaurant orders',
    module: 'orders',
    action: 'read',
    scope: 'restaurant',
  },
  {
    name: 'orders:read:all',
    description: 'View all orders',
    module: 'orders',
    action: 'read',
    scope: 'all',
  },
  {
    name: 'orders:update:own',
    description: 'Update own orders',
    module: 'orders',
    action: 'update',
    scope: 'own',
  },
  {
    name: 'orders:update:assigned',
    description: 'Update assigned orders',
    module: 'orders',
    action: 'update',
    scope: 'assigned',
  },
  {
    name: 'orders:update:all',
    description: 'Update all orders',
    module: 'orders',
    action: 'update',
    scope: 'all',
  },
  {
    name: 'orders:cancel:own',
    description: 'Cancel own orders',
    module: 'orders',
    action: 'cancel',
    scope: 'own',
  },

  // Products
  {
    name: 'products:read',
    description: 'View products',
    module: 'products',
    action: 'read',
  },
  {
    name: 'products:create',
    description: 'Create products',
    module: 'products',
    action: 'create',
  },
  {
    name: 'products:update:own',
    description: 'Update own products',
    module: 'products',
    action: 'update',
    scope: 'own',
  },
  {
    name: 'products:update:all',
    description: 'Update all products',
    module: 'products',
    action: 'update',
    scope: 'all',
  },
  {
    name: 'products:delete:own',
    description: 'Delete own products',
    module: 'products',
    action: 'delete',
    scope: 'own',
  },
  {
    name: 'products:delete:all',
    description: 'Delete all products',
    module: 'products',
    action: 'delete',
    scope: 'all',
  },

  // Categories
  {
    name: 'categories:read',
    description: 'View categories',
    module: 'categories',
    action: 'read',
  },
  {
    name: 'categories:create',
    description: 'Create categories',
    module: 'categories',
    action: 'create',
  },
  {
    name: 'categories:update',
    description: 'Update categories',
    module: 'categories',
    action: 'update',
  },
  {
    name: 'categories:delete',
    description: 'Delete categories',
    module: 'categories',
    action: 'delete',
  },

  // Users (Admin)
  {
    name: 'users:read:all',
    description: 'View all users',
    module: 'users',
    action: 'read',
    scope: 'all',
  },
  {
    name: 'users:update:all',
    description: 'Update all users',
    module: 'users',
    action: 'update',
    scope: 'all',
  },
  {
    name: 'users:delete',
    description: 'Delete users',
    module: 'users',
    action: 'delete',
  },
  {
    name: 'users:manage:roles',
    description: 'Manage user roles',
    module: 'users',
    action: 'manage',
    scope: 'roles',
  },
  {
    name: 'users:manage:permissions',
    description: 'Manage user permissions',
    module: 'users',
    action: 'manage',
    scope: 'permissions',
  },

  // Audit
  {
    name: 'audit:read:own',
    description: 'View own audit logs',
    module: 'audit',
    action: 'read',
    scope: 'own',
  },
  {
    name: 'audit:read:all',
    description: 'View all audit logs',
    module: 'audit',
    action: 'read',
    scope: 'all',
  },

  // Delivery (Rider)
  {
    name: 'delivery:update',
    description: 'Update delivery status',
    module: 'delivery',
    action: 'update',
  },
  {
    name: 'delivery:view:assigned',
    description: 'View assigned deliveries',
    module: 'delivery',
    action: 'read',
    scope: 'assigned',
  },
];

// Default role-permission mappings
const DEFAULT_ROLE_PERMISSIONS: Record<UserRole, string[]> = {
  [UserRole.USER]: [
    'profile:read',
    'profile:update',
    'orders:create',
    'orders:read:own',
    'orders:update:own',
    'orders:cancel:own',
    'products:read',
    'categories:read',
    'audit:read:own',
  ],
  [UserRole.RIDER]: [
    'profile:read',
    'profile:update',
    'orders:read:assigned',
    'orders:update:assigned',
    'delivery:update',
    'delivery:view:assigned',
    'audit:read:own',
  ],
  [UserRole.RESTAURANT]: [
    'profile:read',
    'profile:update',
    'products:read',
    'products:create',
    'products:update:own',
    'products:delete:own',
    'categories:read',
    'orders:read:restaurant',
    'orders:update:own',
    'audit:read:own',
  ],
  [UserRole.ADMIN]: [
    'profile:read',
    'profile:update',
    'products:read',
    'products:create',
    'products:update:all',
    'products:delete:all',
    'categories:read',
    'categories:create',
    'categories:update',
    'categories:delete',
    'orders:read:all',
    'orders:update:all',
    'users:read:all',
    'users:update:all',
    'users:delete',
    'users:manage:roles',
    'users:manage:permissions',
    'audit:read:all',
  ],
};

@Injectable()
export class PermissionsService implements OnModuleInit {
  constructor(
    @InjectModel(Permission.name) private permissionModel: Model<Permission>,
    @InjectModel(RolePermission.name)
    private rolePermissionModel: Model<RolePermission>,
  ) {}

  async onModuleInit() {
    await this.seedPermissions();
    await this.seedRolePermissions();
  }

  private async seedPermissions() {
    for (const perm of DEFAULT_PERMISSIONS) {
      await this.permissionModel.findOneAndUpdate({ name: perm.name }, perm, {
        upsert: true,
        new: true,
      });
    }
  }

  private async seedRolePermissions() {
    for (const [role, permissions] of Object.entries(
      DEFAULT_ROLE_PERMISSIONS,
    )) {
      await this.rolePermissionModel.findOneAndUpdate(
        { role },
        { role, permissions },
        { upsert: true, new: true },
      );
    }
  }

  async getPermissionsForRole(role: UserRole): Promise<string[]> {
    const rolePermission = await this.rolePermissionModel
      .findOne({ role })
      .exec();
    return rolePermission?.permissions || [];
  }

  async getAllPermissions(): Promise<Permission[]> {
    return this.permissionModel.find({ isActive: true }).exec();
  }

  async getPermissionsByModule(module: string): Promise<Permission[]> {
    return this.permissionModel.find({ module, isActive: true }).exec();
  }

  hasPermission(
    userPermissions: string[],
    requiredPermission: string,
  ): boolean {
    // Check exact match
    if (userPermissions.includes(requiredPermission)) {
      return true;
    }

    // Check for wildcard permissions (e.g., 'products:*' grants 'products:read')
    const [module, action] = requiredPermission.split(':');
    return userPermissions.includes(`${module}:*`);
  }

  async updateRolePermissions(
    role: UserRole,
    permissions: string[],
  ): Promise<RolePermission> {
    const rolePermission = await this.rolePermissionModel.findOneAndUpdate(
      { role },
      { permissions },
      { new: true },
    );

    if (!rolePermission) {
      throw new Error('Role not found');
    }

    return rolePermission;
  }
}
