import { Module } from '@nestjs/common';
import { MongooseModule } from '@nestjs/mongoose';
import { CategoriesModule } from '../../categories/src/categories/categories.module';
import { ProductsModule } from '../../products/src/products/products.module';

@Module({
  imports: [
    MongooseModule.forRoot('mongodb://localhost:27017/test-nest'),
    CategoriesModule,
    ProductsModule,
  ],
})
export class AppModule {}
