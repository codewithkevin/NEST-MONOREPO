import { PartialType } from '@nestjs/mapped-types';
import { IsString, IsArray } from 'class-validator';

export class CreateCategoryDto {
  @IsString()
  name: string;

  @IsString()
  description: string;

  @IsArray()
  @IsString({ each: true })
  images: string[];
}

export class UpdateCategoryDto extends PartialType(CreateCategoryDto) {}
