import { Controller, Post, Get, Body } from '@nestjs/common';
import { ProductsService } from './products.service';
import { CreateProductDto } from './dto/create-product.dto';

@Controller('products')
export class ProductsController {
  constructor(private readonly productsService: ProductsService) {}

  @Post()
  create(@Body() input: CreateProductDto) {
    return this.productsService.create(input);
  }

  @Get()
  findAll() {
    return this.productsService.findAll();
  }
}
