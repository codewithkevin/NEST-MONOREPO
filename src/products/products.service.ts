import { Injectable, NotFoundException } from '@nestjs/common';
import { Product } from './entities/product.entity';
import { CategoriesService } from 'src/categories/ categories.service';

@Injectable()
export class ProductsService {
  private products: Product[] = [];

  constructor(private readonly categoriesService: CategoriesService) {}

  create(name: string, price: number, categoryId: number): Product {
    const category = this.categoriesService.findOne(categoryId);

    if (!category) {
      throw new NotFoundException('Category not found');
    }

    const product: Product = {
      id: Date.now(),
      name,
      price,
      categoryId,
      createdAt: new Date(),
    };

    this.products.push(product);
    return product;
  }

  findAll(): Product[] {
    return this.products;
  }
}
