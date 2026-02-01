import {
  Controller,
  Post,
  Get,
  Delete,
  Body,
  Param,
  Req,
  UseGuards,
} from '@nestjs/common';
import { Throttle } from '@nestjs/throttler';
import { AuthService } from './auth.service';
import {
  RegisterDto,
  LoginDto,
  RefreshTokenDto,
  VerifyEmailDto,
  ResendVerificationDto,
  ForgotPasswordDto,
  ResetPasswordDto,
  ChangePasswordDto,
} from './dto';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { Public } from './decorators/public.decorator';
import { CurrentUser } from './decorators/current-user.decorator';

interface AuthenticatedUser {
  id: string;
  email: string;
  role: string;
  jti: string;
}

interface RequestWithIp {
  headers: {
    'x-forwarded-for'?: string;
    'user-agent'?: string;
  };
  ip?: string;
}

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  private getIp(req: RequestWithIp): string {
    return req.headers['x-forwarded-for']?.split(',')[0] || req.ip || 'unknown';
  }

  private getUserAgent(req: RequestWithIp): string | undefined {
    return req.headers['user-agent'];
  }

  // ========== Registration ==========

  @Public()
  @Throttle({ default: { limit: 3, ttl: 60000 } }) // 3 requests per minute
  @Post('register')
  async register(@Body() registerDto: RegisterDto, @Req() req: RequestWithIp) {
    return this.authService.register(
      registerDto,
      this.getIp(req),
      this.getUserAgent(req),
    );
  }

  @Public()
  @Post('verify-email')
  async verifyEmail(
    @Body() verifyDto: VerifyEmailDto,
    @Req() req: RequestWithIp,
  ) {
    return this.authService.verifyEmail(
      verifyDto,
      this.getIp(req),
      this.getUserAgent(req),
    );
  }

  @Public()
  @Throttle({ default: { limit: 3, ttl: 300000 } }) // 3 requests per 5 minutes
  @Post('resend-verification')
  async resendVerification(
    @Body() resendDto: ResendVerificationDto,
    @Req() req: RequestWithIp,
  ) {
    return this.authService.resendVerification(
      resendDto.email,
      this.getIp(req),
      this.getUserAgent(req),
    );
  }

  // ========== Login ==========

  @Public()
  @Throttle({ default: { limit: 5, ttl: 60000 } }) // 5 requests per minute
  @Post('login')
  async login(@Body() loginDto: LoginDto, @Req() req: RequestWithIp) {
    return this.authService.login(
      loginDto,
      this.getIp(req),
      this.getUserAgent(req),
    );
  }

  // ========== Token Management ==========

  @Public()
  @Post('refresh')
  async refreshTokens(
    @Body() refreshDto: RefreshTokenDto,
    @Req() req: RequestWithIp,
  ) {
    return this.authService.refreshTokens(
      refreshDto.refreshToken,
      this.getIp(req),
      this.getUserAgent(req),
    );
  }

  // ========== Logout ==========

  @UseGuards(JwtAuthGuard)
  @Post('logout')
  async logout(
    @CurrentUser() user: AuthenticatedUser,
    @Req() req: RequestWithIp,
  ) {
    await this.authService.logout(
      user.id,
      user.jti,
      this.getIp(req),
      this.getUserAgent(req),
    );
    return { message: 'Logged out successfully' };
  }

  @UseGuards(JwtAuthGuard)
  @Post('logout-all')
  async logoutAll(
    @CurrentUser() user: AuthenticatedUser,
    @Req() req: RequestWithIp,
  ) {
    await this.authService.logoutAll(
      user.id,
      this.getIp(req),
      this.getUserAgent(req),
    );
    return { message: 'Logged out from all devices' };
  }

  // ========== Sessions ==========

  @UseGuards(JwtAuthGuard)
  @Get('sessions')
  async getSessions(@CurrentUser() user: AuthenticatedUser) {
    return this.authService.getActiveSessions(user.id);
  }

  @UseGuards(JwtAuthGuard)
  @Delete('sessions/:id')
  async revokeSession(
    @CurrentUser() user: AuthenticatedUser,
    @Param('id') sessionId: string,
    @Req() req: RequestWithIp,
  ) {
    await this.authService.revokeSession(
      user.id,
      sessionId,
      this.getIp(req),
      this.getUserAgent(req),
    );
    return { message: 'Session revoked successfully' };
  }

  // ========== Password Reset ==========

  @Public()
  @Throttle({ default: { limit: 3, ttl: 300000 } }) // 3 requests per 5 minutes
  @Post('forgot-password')
  async forgotPassword(
    @Body() forgotPasswordDto: ForgotPasswordDto,
    @Req() req: RequestWithIp,
  ) {
    return this.authService.forgotPassword(
      forgotPasswordDto,
      this.getIp(req),
      this.getUserAgent(req),
    );
  }

  @Public()
  @Post('reset-password')
  async resetPassword(
    @Body() resetPasswordDto: ResetPasswordDto,
    @Req() req: RequestWithIp,
  ) {
    return this.authService.resetPassword(
      resetPasswordDto,
      this.getIp(req),
      this.getUserAgent(req),
    );
  }

  @UseGuards(JwtAuthGuard)
  @Post('change-password')
  async changePassword(
    @CurrentUser() user: AuthenticatedUser,
    @Body() changePasswordDto: ChangePasswordDto,
    @Req() req: RequestWithIp,
  ) {
    return this.authService.changePassword(
      user.id,
      changePasswordDto,
      this.getIp(req),
      this.getUserAgent(req),
    );
  }
}
