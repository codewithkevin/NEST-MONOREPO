import {
  Injectable,
  NotFoundException,
  ConflictException,
} from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model, Types } from 'mongoose';
import * as bcrypt from 'bcrypt';
import { User } from './entities/user.entity';
import { UpdateUserDto, AdminUpdateUserDto, UserResponseDto } from './dto';
import { UserRole, UserStatus } from '../common/enums';

@Injectable()
export class UsersService {
  constructor(@InjectModel(User.name) private userModel: Model<User>) {}

  async findById(id: string): Promise<User | null> {
    return this.userModel.findById(id).exec();
  }

  async findByEmail(email: string): Promise<User | null> {
    return this.userModel.findOne({ email: email.toLowerCase() }).exec();
  }

  async create(data: {
    email: string;
    password: string;
    firstName: string;
    lastName: string;
    phone?: string;
    role?: UserRole;
  }): Promise<User> {
    const existingUser = await this.findByEmail(data.email);
    if (existingUser) {
      throw new ConflictException('User with this email already exists');
    }

    const hashedPassword = await bcrypt.hash(data.password, 10);
    const user = new this.userModel({
      ...data,
      email: data.email.toLowerCase(),
      password: hashedPassword,
      role: data.role || UserRole.USER,
      status: UserStatus.PENDING_VERIFICATION,
      emailVerified: false,
    });

    return user.save();
  }

  async updateProfile(userId: string, updateDto: UpdateUserDto): Promise<User> {
    const user = await this.userModel
      .findByIdAndUpdate(userId, updateDto, { new: true })
      .exec();

    if (!user) {
      throw new NotFoundException('User not found');
    }

    return user;
  }

  async adminUpdateUser(
    userId: string,
    updateDto: AdminUpdateUserDto,
  ): Promise<User> {
    const user = await this.userModel
      .findByIdAndUpdate(userId, updateDto, { new: true })
      .exec();

    if (!user) {
      throw new NotFoundException('User not found');
    }

    return user;
  }

  async changeUserRole(userId: string, newRole: UserRole): Promise<User> {
    const user = await this.userModel
      .findByIdAndUpdate(userId, { role: newRole }, { new: true })
      .exec();

    if (!user) {
      throw new NotFoundException('User not found');
    }

    return user;
  }

  async verifyEmail(userId: string): Promise<User> {
    const user = await this.userModel
      .findByIdAndUpdate(
        userId,
        {
          emailVerified: true,
          status: UserStatus.ACTIVE,
        },
        { new: true },
      )
      .exec();

    if (!user) {
      throw new NotFoundException('User not found');
    }

    return user;
  }

  async lockAccount(userId: string, reason?: string): Promise<User> {
    const user = await this.userModel
      .findByIdAndUpdate(
        userId,
        {
          status: UserStatus.LOCKED,
          lockedAt: new Date(),
          lockReason: reason || 'Too many failed login attempts',
        },
        { new: true },
      )
      .exec();

    if (!user) {
      throw new NotFoundException('User not found');
    }

    return user;
  }

  async unlockAccount(userId: string): Promise<User> {
    const user = await this.userModel
      .findByIdAndUpdate(
        userId,
        {
          status: UserStatus.ACTIVE,
          lockedAt: null,
          lockReason: null,
          failedLoginAttempts: 0,
        },
        { new: true },
      )
      .exec();

    if (!user) {
      throw new NotFoundException('User not found');
    }

    return user;
  }

  async updateLoginInfo(userId: string, ip: string): Promise<void> {
    await this.userModel
      .findByIdAndUpdate(userId, {
        lastLoginAt: new Date(),
        lastLoginIp: ip,
        failedLoginAttempts: 0,
      })
      .exec();
  }

  async incrementFailedAttempts(userId: string): Promise<number> {
    const user = await this.userModel
      .findByIdAndUpdate(
        userId,
        { $inc: { failedLoginAttempts: 1 } },
        { new: true },
      )
      .exec();

    return user?.failedLoginAttempts || 0;
  }

  async changePassword(userId: string, newPassword: string): Promise<void> {
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await this.userModel
      .findByIdAndUpdate(userId, { password: hashedPassword })
      .exec();
  }

  async validatePassword(user: User, password: string): Promise<boolean> {
    return bcrypt.compare(password, user.password);
  }

  async findAllUsers(
    page = 1,
    limit = 20,
    role?: UserRole,
    status?: UserStatus,
  ) {
    const query: Record<string, unknown> = {};
    if (role) query.role = role;
    if (status) query.status = status;

    const [users, total] = await Promise.all([
      this.userModel
        .find(query)
        .select('-password')
        .sort({ createdAt: -1 })
        .skip((page - 1) * limit)
        .limit(limit)
        .exec(),
      this.userModel.countDocuments(query).exec(),
    ]);

    return { users, total, page, limit };
  }

  async updatePermissions(
    userId: string,
    permissions: string[],
  ): Promise<User> {
    const user = await this.userModel
      .findByIdAndUpdate(userId, { permissions }, { new: true })
      .exec();

    if (!user) {
      throw new NotFoundException('User not found');
    }

    return user;
  }

  toResponseDto(user: User): UserResponseDto {
    return {
      id: user._id.toString(),
      email: user.email,
      firstName: user.firstName,
      lastName: user.lastName,
      phone: user.phone,
      role: user.role,
      status: user.status,
      emailVerified: user.emailVerified,
      permissions: user.permissions,
      lastLoginAt: user.lastLoginAt,
      createdAt: user.createdAt,
    };
  }
}
