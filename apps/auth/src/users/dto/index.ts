import {
  IsString,
  IsOptional,
  MaxLength,
  MinLength,
  IsEmail,
} from 'class-validator';
import { PartialType } from '@nestjs/mapped-types';

export class UpdateUserDto {
  @IsString()
  @IsOptional()
  @MinLength(2)
  @MaxLength(50)
  firstName?: string;

  @IsString()
  @IsOptional()
  @MinLength(2)
  @MaxLength(50)
  lastName?: string;

  @IsString()
  @IsOptional()
  phone?: string;
}

export class AdminUpdateUserDto extends PartialType(UpdateUserDto) {
  @IsEmail()
  @IsOptional()
  email?: string;
}

export class UserResponseDto {
  id: string;
  email: string;
  firstName: string;
  lastName: string;
  phone?: string;
  role: string;
  status: string;
  emailVerified: boolean;
  permissions: string[];
  lastLoginAt?: Date;
  createdAt: Date;
}

export class UserListResponseDto {
  users: UserResponseDto[];
  total: number;
  page: number;
  limit: number;
}
