import { createParamDecorator, ExecutionContext } from '@nestjs/common';

interface AuthenticatedUser {
  id: string;
  email: string;
  role: string;
  permissions: string[];
  jti: string;
}

export const CurrentUser = createParamDecorator(
  (data: keyof AuthenticatedUser | undefined, ctx: ExecutionContext) => {
    const request = ctx
      .switchToHttp()
      .getRequest<{ user: AuthenticatedUser }>();
    const user = request.user;

    if (!user) {
      return null;
    }

    return data ? user[data] : user;
  },
);
