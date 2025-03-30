<p align="center">
  <a href="http://nestjs.com/" target="blank"><img src="https://nestjs.com/img/logo-small.svg" width="200" alt="Nest Logo" /></a>
</p>

[circleci-image]: https://img.shields.io/circleci/build/github/nestjs/nest/master?token=abc123def456
[circleci-url]: https://circleci.com/gh/nestjs/nest

  <p align="center">A progressive <a href="http://nodejs.org" target="_blank">Node.js</a> framework for building efficient and scalable server-side applications.</p>
    <p align="center">
<a href="https://www.npmjs.com/~nestjscore" target="_blank"><img src="https://img.shields.io/npm/v/@nestjs/core.svg" alt="NPM Version" /></a>
<a href="https://www.npmjs.com/~nestjscore" target="_blank"><img src="https://img.shields.io/npm/l/@nestjs/core.svg" alt="Package License" /></a>
<a href="https://www.npmjs.com/~nestjscore" target="_blank"><img src="https://img.shields.io/npm/dm/@nestjs/common.svg" alt="NPM Downloads" /></a>
<a href="https://circleci.com/gh/nestjs/nest" target="_blank"><img src="https://img.shields.io/circleci/build/github/nestjs/nest/master" alt="CircleCI" /></a>
<a href="https://coveralls.io/github/nestjs/nest?branch=master" target="_blank"><img src="https://coveralls.io/repos/github/nestjs/nest/badge.svg?branch=master#9" alt="Coverage" /></a>
<a href="https://discord.gg/G7Qnnhy" target="_blank"><img src="https://img.shields.io/badge/discord-online-brightgreen.svg" alt="Discord"/></a>
<a href="https://opencollective.com/nest#backer" target="_blank"><img src="https://opencollective.com/nest/backers/badge.svg" alt="Backers on Open Collective" /></a>
<a href="https://opencollective.com/nest#sponsor" target="_blank"><img src="https://opencollective.com/nest/sponsors/badge.svg" alt="Sponsors on Open Collective" /></a>
  <a href="https://paypal.me/kamilmysliwiec" target="_blank"><img src="https://img.shields.io/badge/Donate-PayPal-ff3f59.svg"/></a>
    <a href="https://opencollective.com/nest#sponsor"  target="_blank"><img src="https://img.shields.io/badge/Support%20us-Open%20Collective-41B883.svg" alt="Support us"></a>
  <a href="https://twitter.com/nestframework" target="_blank"><img src="https://img.shields.io/twitter/follow/nestframework.svg?style=social&label=Follow"></a>
</p>
  <!--[![Backers on Open Collective](https://opencollective.com/nest/backers/badge.svg)](https://opencollective.com/nest#backer)
  [![Sponsors on Open Collective](https://opencollective.com/nest/sponsors/badge.svg)](https://opencollective.com/nest#sponsor)-->

## Description

[Nest](https://github.com/nestjs/nest) framework TypeScript starter repository.

## Installation

```bash
$ pnpm install
```

## Docker
Start containers in detached / background mode
```shell
$ docker-compose up -d
```

Stop containers
```shell
$ docker-compose down**
```

## Running the app

```bash
# development
$ pnpm run start

# watch mode
$ pnpm run start:dev

# production mode
$ pnpm run start:prod
```

## Test

```bash
# unit tests
$ pnpm run test

# e2e tests
$ pnpm run test:e2e

# test coverage
$ pnpm run test:cov
```

## Security Features

### STRIDE Threat Modeling

This project includes an integrated security threat modeling tool that uses Google AI to analyze endpoints, data entities, and application architecture to identify potential vulnerabilities.

To generate a threat model report:

```bash
# Production mode (requires Google AI API key)
$ export GOOGLE_API_KEY=your_api_key_here
$ pnpm run threat-model -- --output-path ./reports

# Development mode (no API key needed, uses mock responses)
$ export USE_MOCK_RESPONSE=true
$ pnpm run threat-model -- --output-path ./reports
```

For detailed instructions, see [src/threat-modelling/README.md](src/threat-modelling/README.md).

## Migration TypeORM example
```javascript
/* typeorm-cli.config.ts */
export default new DataSource({
    type: 'postgres',
    host: 'localhost',
    port: 5432,
    username: 'postgres',
    password: 'pass123',
    database: 'postgres',
    entities: [],
    migrations: [],
});
```

### Creating a TypeOrm Migration

```shell
$ npx typeorm migration:create src/migrations/CoffeeRefactor
```

#### CoffeeRefactor being the NAME we are giving "this" migration

```typescript
public async up(queryRunner: QueryRunner): Promise<any> {
  await queryRunner.query(
    `ALTER TABLE "coffee" RENAME COLUMN "name" TO "title"`,
  );
}

public async down(queryRunner: QueryRunner): Promise<any> {
  await queryRunner.query(
    `ALTER TABLE "coffee" RENAME COLUMN "title" TO "name"`,
  );
}
```

#### RUNNING MIGRATIONS

> 💡 IMPORTANT 💡
You must BUILD your Nest project (so that everything is output to the `/dist/` folder,
before a Migration can run, it needs compiled files.

```shell
// Compile project first
$ pnpm run build

// Run migration(s)
$ npx typeorm migration:run -d dist/typeorm-cli.config

// REVERT migration(s)
$ npx typeorm migration:revert -d dist/typeorm-cli.config

// Let TypeOrm generate migrations (for you)
$ npx typeorm migration:generate src/migrations/SchemaSync -d dist/typeorm-cli.config
```

# Troubleshooting
1. If the error message is "aggregateError":
```shell
When running nestjs project I have the issue:
aggregateError: 
    at internalConnectMultiple (node:net:1114:18)
    at afterConnectMultiple (node:net:1667:5)
    at TCPConnectWrap.callbackTrampoline (node:internal/async_hooks:130:17)
Waiting for the debugger to disconnect..
```

## Solution:
The error message, "AggregateError," typically indicates that there was an issue when connecting to a network resource. In a NestJS application, this could relate to issues with connecting to databases, external services, or other network-related operations.

- Check Database Connection: if NestJS application is connecting to a database, ensure that the database server is up and running, and that the connection details (such as host, port, username, and password) are correctly configured in your application's configuration file, check your `.env` file.

On this case run Docker compose to start database container:
```shell
$ docker-compose up -d
```

## Support

Nest is an MIT-licensed open source project. It can grow thanks to the sponsors and support by the amazing backers. If you'd like to join them, please [read more here](https://docs.nestjs.com/support).

## Stay in touch

- Author - [Kamil Myśliwiec](https://kamilmysliwiec.com)
- Website - [https://nestjs.com](https://nestjs.com/)
- Twitter - [@nestframework](https://twitter.com/nestframework)

## License

Nest is [MIT licensed](LICENSE).

