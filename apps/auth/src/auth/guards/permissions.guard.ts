import { Injectable, CanActivate, ExecutionContext } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { PERMISSIONS_KEY } from '../decorators/permissions.decorator';

interface AuthenticatedUser {
  id: string;
  email: string;
  role: string;
  permissions: string[];
}

@Injectable()
export class PermissionsGuard implements CanActivate {
  constructor(private reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    const requiredPermissions = this.reflector.getAllAndOverride<string[]>(
      PERMISSIONS_KEY,
      [context.getHandler(), context.getClass()],
    );

    if (!requiredPermissions || requiredPermissions.length === 0) {
      return true;
    }

    const { user } = context
      .switchToHttp()
      .getRequest<{ user: AuthenticatedUser }>();

    if (!user) {
      return false;
    }

    // Check if user has any of the required permissions
    return requiredPermissions.some(
      (permission) =>
        user.permissions.includes(permission) ||
        user.permissions.includes(`${permission.split(':')[0]}:*`), // Wildcard support
    );
  }
}
