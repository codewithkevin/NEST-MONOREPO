import {
  Controller,
  Get,
  Patch,
  Param,
  Body,
  Query,
  UseGuards,
} from '@nestjs/common';
import { UsersService } from './users.service';
import { UpdateUserDto, AdminUpdateUserDto } from './dto';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { RolesGuard } from '../auth/guards/roles.guard';
import { Roles } from '../auth/decorators/roles.decorator';
import { CurrentUser } from '../auth/decorators/current-user.decorator';
import { UserRole, UserStatus } from '../common/enums';

@Controller('users')
@UseGuards(JwtAuthGuard, RolesGuard)
export class UsersController {
  constructor(private readonly usersService: UsersService) {}

  // ========== Current User Endpoints ==========

  @Get('me')
  async getProfile(@CurrentUser() currentUser: { id: string }) {
    const user = await this.usersService.findById(currentUser.id);
    if (!user) {
      throw new Error('User not found');
    }
    return this.usersService.toResponseDto(user);
  }

  @Patch('me')
  async updateProfile(
    @CurrentUser() currentUser: { id: string },
    @Body() updateDto: UpdateUserDto,
  ) {
    const user = await this.usersService.updateProfile(
      currentUser.id,
      updateDto,
    );
    return this.usersService.toResponseDto(user);
  }

  // ========== Admin Endpoints ==========

  @Get()
  @Roles(UserRole.ADMIN)
  async findAll(
    @Query('page') page = 1,
    @Query('limit') limit = 20,
    @Query('role') role?: UserRole,
    @Query('status') status?: UserStatus,
  ) {
    const result = await this.usersService.findAllUsers(
      Number(page),
      Number(limit),
      role,
      status,
    );

    return {
      users: result.users.map((u) => this.usersService.toResponseDto(u)),
      total: result.total,
      page: result.page,
      limit: result.limit,
    };
  }

  @Get(':id')
  @Roles(UserRole.ADMIN)
  async findOne(@Param('id') id: string) {
    const user = await this.usersService.findById(id);
    if (!user) {
      throw new Error('User not found');
    }
    return this.usersService.toResponseDto(user);
  }

  @Patch(':id')
  @Roles(UserRole.ADMIN)
  async adminUpdate(
    @Param('id') id: string,
    @Body() updateDto: AdminUpdateUserDto,
  ) {
    const user = await this.usersService.adminUpdateUser(id, updateDto);
    return this.usersService.toResponseDto(user);
  }

  @Patch(':id/role')
  @Roles(UserRole.ADMIN)
  async changeRole(@Param('id') id: string, @Body('role') role: UserRole) {
    const user = await this.usersService.changeUserRole(id, role);
    return this.usersService.toResponseDto(user);
  }

  @Patch(':id/unlock')
  @Roles(UserRole.ADMIN)
  async unlockAccount(@Param('id') id: string) {
    const user = await this.usersService.unlockAccount(id);
    return this.usersService.toResponseDto(user);
  }

  @Patch(':id/permissions')
  @Roles(UserRole.ADMIN)
  async updatePermissions(
    @Param('id') id: string,
    @Body('permissions') permissions: string[],
  ) {
    const user = await this.usersService.updatePermissions(id, permissions);
    return this.usersService.toResponseDto(user);
  }
}
