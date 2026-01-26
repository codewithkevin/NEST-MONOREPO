import { IsString, IsArray } from 'class-validator';

/* eslint-disable @typescript-eslint/no-unsafe-call */
export class CreateCategoryDto {
  @IsString()
  name: string;

  @IsString()
  description: string;

  @IsArray()
  @IsString({ each: true })
  images: string[];
}
