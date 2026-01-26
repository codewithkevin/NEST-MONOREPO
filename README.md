<p align="center">
  <a href="http://nestjs.com/" target="blank"><img src="https://nestjs.com/img/logo-small.svg" width="120" alt="Nest Logo" /></a>
</p>

[circleci-image]: https://img.shields.io/circleci/build/github/nestjs/nest/master?token=abc123def456
[circleci-url]: https://circleci.com/gh/nestjs/nest

  <p align="center">A progressive <a href="http://nodejs.org" target="_blank">Node.js</a> framework for building efficient and scalable server-side applications.</p>
    <p align="center">
<a href="https://www.npmjs.com/~nestjscore" target="_blank"><img src="https://img.shields.io/npm/v/@nestjs/core.svg" alt="NPM Version" /></a>
<a href="https://www.npmjs.com/~nestjscore" target="_blank"><img src="https://img.shields.io/npm/l/@nestjs/core.svg" alt="Package License" /></a>
<a href="https://www.npmjs.com/~nestjscore" target="_blank"><img src="https://img.shields.io/npm/dm/@nestjs/common.svg" alt="NPM Downloads" /></a>
<a href="https://circleci.com/gh/nestjs/nest" target="_blank"><img src="https://img.shields.io/circleci/build/github/nestjs/nest/master" alt="CircleCI" /></a>
<a href="https://discord.gg/G7Qnnhy" target="_blank"><img src="https://img.shields.io/badge/discord-online-brightgreen.svg" alt="Discord"/></a>
<a href="https://opencollective.com/nest#backer" target="_blank"><img src="https://opencollective.com/nest/backers/badge.svg" alt="Backers on Open Collective" /></a>
<a href="https://opencollective.com/nest#sponsor" target="_blank"><img src="https://opencollective.com/nest/sponsors/badge.svg" alt="Sponsors on Open Collective" /></a>
  <a href="https://paypal.me/kamilmysliwiec" target="_blank"><img src="https://img.shields.io/badge/Donate-PayPal-ff3f59.svg" alt="Donate us"/></a>
    <a href="https://opencollective.com/nest#sponsor"  target="_blank"><img src="https://img.shields.io/badge/Support%20us-Open%20Collective-41B883.svg" alt="Support us"></a>
  <a href="https://twitter.com/nestframework" target="_blank"><img src="https://img.shields.io/twitter/follow/nestframework.svg?style=social&label=Follow" alt="Follow us on Twitter"></a>
</p>
  <!--[![Backers on Open Collective](https://opencollective.com/nest/backers/badge.svg)](https://opencollective.com/nest#backer)
  [![Sponsors on Open Collective](https://opencollective.com/nest/sponsors/badge.svg)](https://opencollective.com/nest#sponsor)-->

## Learning Guide 📚

Welcome to this NestJS Monorepo project! This repository is designed for learning microservices architecture.

### 🏗 Project Structure

This project is a **Monorepo** containing multiple applications:

1.  **test-nest** (`apps/test-nest`): The main application (or Gateway).
2.  **categories** (`apps/categories`): Microservice handling category operations.
3.  **products** (`apps/products`): Microservice handling product operations.

### 🚀 Getting Started

#### 1. Installation

```bash
yarn install
```

#### 2. Running Applications

You can run each application independently:

**Main App:**

```bash
# Run the main application
nest start
# Watch mode
nest start --watch
```

**Microservices:**

```bash
# Run the Categories service
nest start categories --watch

# Run the Products service
nest start products --watch
```

### 🧠 Core Concepts to Learn Here

- **Monorepo Configuration**: Check `nest-cli.json` to see how projects are mapped.
- **Microservices**: Explore `main.ts` in apps to see `MicroserviceOptions`.
- **Modules**: See how features are isolated (e.g., `ProductsModule`).

### 🔗 Resources

- [NestJS Monorepo Documentation](https://docs.nestjs.com/cli/monorepo)
- [NestJS Microservices](https://docs.nestjs.com/microservices/basics)
