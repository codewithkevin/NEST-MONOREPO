import { PartialType } from '@nestjs/mapped-types';
import { IsArray, IsNumber, IsString } from 'class-validator';

export class CreateProductDto {
  @IsString()
  name: string;

  @IsNumber()
  price: number;

  @IsString()
  description: string;

  @IsArray()
  @IsString({ each: true })
  category_ids: string[];

  @IsArray()
  @IsString({ each: true })
  tags: string[];

  @IsArray()
  @IsString({ each: true })
  images: string[];
}

export class UpdateProductDto extends PartialType(CreateProductDto) {}
