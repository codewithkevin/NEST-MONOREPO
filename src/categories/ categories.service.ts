import { Injectable } from '@nestjs/common';
import { Category } from './dto/create-category.dto';

@Injectable()
export class CategoriesService {
  private categories: Category[] = [];

  create(name: string): Category {
    const category = { id: Date.now(), name };
    this.categories.push(category);
    return category;
  }

  findAll() {
    return this.categories;
  }

  findOne(id: number) {
    return this.categories.find((c) => c.id === id);
  }
}
