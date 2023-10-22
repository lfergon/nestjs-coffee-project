import { HttpStatus, INestApplication } from '@nestjs/common';
import { TestingModule, Test } from '@nestjs/testing';
import { CoffeesModule } from '../../src/coffees/coffees.module';
import { TypeOrmModule } from '@nestjs/typeorm';
import { beforeAll, describe, it, afterAll } from 'vitest';
import request from 'supertest';

const configurationDataSource = {
  type: 'postgres',
  host: 'localhost',
  port: 5433,
  username: 'postgres',
  password: 'postgres',
  database: 'postgres',
  autoLoadEntities: true,
  synchronize: true,
} as const;

describe('[Feature] Coffees - /coffees', () => {
  let app: INestApplication;

  const mockCoffeeCreation = {
    title: 'Shipwreck Roast',
    brand: 'Buddy Brew',
    flavors: ['chocolate', 'vanilla'],
    recommendations: 3,
  };

  beforeAll(async () => {
    const moduleFixture: TestingModule = await Test.createTestingModule({
      imports: [CoffeesModule, TypeOrmModule.forRoot(configurationDataSource)],
    }).compile();

    app = moduleFixture.createNestApplication();
    await app.init();
  });

  describe('Create [POST /]', () => {
    it('creates coffee and returns it', async () => {
      const { body } = await request(app.getHttpServer())
        .post('/coffees')
        .send(mockCoffeeCreation)
        .expect(201)
        .expect('Content-Type', /json/)
        .expect(HttpStatus.CREATED);
    });
  });

  describe('Get all [GET /]', () => {
    it('returns all coffees', async () => {
      const { body } = await request(app.getHttpServer())
        .get('/coffees')
        .expect(200)
        .expect('Content-Type', /json/)
        .expect(HttpStatus.OK);
    });
  });

  describe('Get one [GET /:id]', () => {
    it('returns one coffee', async () => {
      const { body } = await request(app.getHttpServer())
        .get('/coffees/2')
        .expect(200)
        .expect('Content-Type', /json/)
        .expect(HttpStatus.OK);
    });
  });

  describe('Update one [PATCH /:id]', () => {
    it('updates one coffee', async () => {
      const { body } = await request(app.getHttpServer())
        .patch('/coffees/2')
        .send({ title: 'new title' })
        .expect(200)
        .expect('Content-Type', /json/)
        .expect(HttpStatus.OK);
    });
  });

  describe('Delete one [DELETE /:id]', () => {
    it('deletes one coffee', async () => {
      const { body } = await request(app.getHttpServer())
        .delete('/coffees/2')
        .expect(200)
        .expect('Content-Type', /json/)
        .expect(HttpStatus.OK);
    });
  });

  afterAll(async () => {
    await app.close();
  });
});
