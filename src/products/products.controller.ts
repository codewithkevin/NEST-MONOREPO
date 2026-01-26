import { Controller, Post, Get, Body } from '@nestjs/common';
import { ProductsService } from './products.service';

@Controller('products')
export class ProductsController {
  constructor(private readonly productsService: ProductsService) {}

  @Post()
  create(
    @Body('name') name: string,
    @Body('price') price: number,
    @Body('categoryId') categoryId: number,
  ) {
    return this.productsService.create(name, price, categoryId);
  }

  @Get()
  findAll() {
    return this.productsService.findAll();
  }
}
