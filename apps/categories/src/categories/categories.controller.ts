import { Controller, Get, Post, Body } from '@nestjs/common';
import { CategoriesService } from './categories.service';
import { CreateCategoryDto } from './dto/create-category.dto';

@Controller('categories')
export class CategoriesController {
  constructor(private readonly categoriesService: CategoriesService) {}

  @Post()
  create(@Body() input: CreateCategoryDto) {
    const { name, description, images } = input;
    return this.categoriesService.create(name, description, images);
  }

  @Get()
  findAll() {
    return this.categoriesService.findAll();
  }
}
