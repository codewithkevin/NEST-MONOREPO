# Project Technical Documentation & Learning Guide 🚀

This document provides a comprehensive overview of the **NestJS Monorepo** project, its architecture, and resources for learning the technologies used.

---

## 📖 Table of Contents

1. [Project Overview](#project-overview)
2. [Architecture Deep Dive](#architecture-deep-dive)
3. [Technology Stack](#technology-stack)
4. [Monorepos vs. Microservices](#monorepos-vs-microservices)
5. [Core Features & Logic](#core-features--logic)
6. [Validation (class-validator vs. Zod/Joi)](#6-validation-class-validator-vs-zodjoi)
7. [Learning Resources](#learning-resources)

---

## 1. Project Overview

This project is a backend system built to manage **Products** and **Categories**. It is structured as a **Monorepo**, meaning multiple related applications and services live in a single repository.

### Applications:

- **test-nest**: The "main" application (Entry point).
- **products**: Service handling product-related business logic and data.
- **categories**: Service handling category-related business logic and data.

---

## 2. Architecture Deep Dive

The project uses a **Monorepo Architecture** managed by the Nest CLI.

### Directory Structure

```text
.
├── apps/
│   ├── categories/   # Category service
│   ├── products/     # Product service
│   └── test-nest/    # Main gateway application
├── nest-cli.json     # Monorepo configuration
└── package.json      # Shared dependencies
```

### Communication Pattern

Currently, these services are configured as **independent HTTP servers**.

- Each service runs on its own port (default is 3000, but usually configured via `.env`).
- In a full microservices setup, they might communicate via TCP, Redis, or RabbitMQ using `@nestjs/microservices`.

---

## 3. Technology Stack

- **Framework**: [NestJS](https://nestjs.com/) (Node.js)
- **Database**: [MongoDB](https://www.mongodb.com/)
- **ODM**: [Mongoose](https://mongoosejs.com/) with `@nestjs/mongoose`
- **Language**: [TypeScript](https://www.typescriptlang.org/)
- **Package Manager**: [Yarn](https://yarnpkg.com/)

---

## 4. Monorepos vs. Microservices

It is common to be confused between these two terms:

| Feature          | Monorepo                                                               | Microservices                                                                            |
| :--------------- | :--------------------------------------------------------------------- | :--------------------------------------------------------------------------------------- |
| **Definition**   | A strategy where you keep **multiple projects** in one Git repository. | An architectural style where you split an app into **independent services**.             |
| **This Project** | **Yes**. It uses NestJS Monorepo mode.                                 | **Sort of**. The apps are separated logically like microservices but currently use HTTP. |

> [!TIP]
> This project is a great starting point for learning microservices because the logic is already separated into different "apps" within the `apps/` directory.

---

## 5. Core Features & Logic

### Product-Category Relationship

Recently, the project was updated to support a **Many-to-Many** style relationship where a product can belong to multiple categories.

- **Storage**: Products store an array of `category_ids`.
- **Logic**: Use the `ProductsService` to manage these associations.

### How to Run

- Start Categories: `nest start categories --watch`
- Start Products: `nest start products --watch`

---

## 6. Validation (class-validator vs. Zod/Joi)

NestJS is heavily built on classes and decorators. Therefore, **`class-validator`** is the most idiomatic (standard) way to handle validation in this ecosystem.

### Why `class-validator`?

- **Single Source of Truth**: Your DTO class defines both the TypeScript interface and the validation rules.
- **Auto-Transformation**: Nest can automatically convert data (e.g., string to number) using `class-transformer`.
- **Ecosystem Support**: Most NestJS plugins (like Swagger) automatically generate documentation from your `class-validator` decorators.

### Comparison

| Feature         | class-validator                | Zod / Joi                                     |
| :-------------- | :----------------------------- | :-------------------------------------------- |
| **Approach**    | Decorator-based (on classes)   | Schema-based (objects)                        |
| **Integration** | Direct (built into Nest pipes) | Requires custom pipes or third-party wrappers |
| **Standard**    | NestJS Standard                | Generic Node.js / Frontend                    |

---

## 7. Learning Resources

### NestJS Basics

- [Official NestJS Documentation](https://docs.nestjs.com/) - Start with "Overview".
- [NestJS Monorepo Guide](https://docs.nestjs.com/cli/monorepo) - Learn how `nest-cli.json` works.
- [First Steps Video](https://www.youtube.com/watch?v=GHTA143_b-s) - Great for visual learners.

### MongoDB & Mongoose with Nest

- [NestJS + Mongoose Docs](https://docs.nestjs.com/techniques/mongodb) - How to use `@Schema()`, `@Prop()`, and `MongooseModule`.
- [Mongoose Official Docs](https://mongoosejs.com/docs/guide.html) - Understanding Schemas and Models.

### Architecture Patterns

- [Introduction to Microservices](https://microservices.io/) - Conceptual overview.
- [NestJS Microservices Docs](https://docs.nestjs.com/microservices/basics) - How to transform these HTTP apps into true microservices (TCP, Redis, etc.).

---

_Happy Coding! 🚀_
