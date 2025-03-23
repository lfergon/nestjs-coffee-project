# CLAUDE.md - NestJS Project Guide

## Build & Run Commands
- Build: `pnpm run build`
- Start: `pnpm run start`
- Dev mode: `pnpm run start:dev`
- Lint: `pnpm run lint`
- Format: `pnpm run format`

## Test Commands
- Run all tests: `pnpm run test`
- Run single test: `pnpm run test -- path/to/test.spec.ts`
- Run test in watch mode: `pnpm run test:watch -- path/to/test.spec.ts`
- E2E tests: `pnpm run test:e2e`
- Coverage: `pnpm run test:cov`

## Docker Commands
- Start DB: `docker-compose up -d`
- Stop DB: `docker-compose down`

## Code Style Guidelines
- Use single quotes for strings
- 120 character line length
- 2 spaces for indentation
- Use trailing commas in multiline structures
- Use TypeORM decorators for entity definitions
- Follow NestJS module/service/controller pattern
- Descriptive exception messages with IDs
- Use Data Transfer Objects (DTOs) for input validation
- Use TypeScript types/interfaces for all parameters
- Put classes/interfaces in separate files
- Error handling: Throw specific NestJS exceptions (NotFoundException, etc.)
- Use dependency injection via constructor
- Transactions for operations that modify multiple entities