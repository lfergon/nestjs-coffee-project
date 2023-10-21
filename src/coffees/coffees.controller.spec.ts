import { Test, TestingModule } from '@nestjs/testing';
import { CoffeesController } from './coffees.controller';
import { DataSource } from 'typeorm';
import { CoffeesService } from './coffees.service';
import { PaginationQueryDto } from '../common/dto/pagination-query.dto';
import { getRepositoryToken } from '@nestjs/typeorm';
import { Coffee } from './entities/coffee.entity';
import { Flavor } from './entities/flavor.entity';
import { describe, beforeEach, vi, it, expect, Mock } from 'vitest';

// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-ignore
const dataSourceMockFactory: () => MockType<DataSource> = vi.fn(() => ({
  getCoffee: vi.fn(),
}));

type MockType<T> = {
  [P in keyof T]?: Mock;
};

describe('CoffeesController', () => {
  let coffeesController: CoffeesController;
  let coffeesService: CoffeesService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [CoffeesController],
      providers: [
        CoffeesService,
        {
          provide: getRepositoryToken(Coffee),
          useValue: {},
        },
        {
          provide: getRepositoryToken(Flavor),
          useValue: {},
        },
        {
          provide: DataSource,
          useFactory: dataSourceMockFactory,
        },
      ],
    }).compile();

    coffeesController = module.get<CoffeesController>(CoffeesController);
    coffeesService = module.get<CoffeesService>(CoffeesService);
  });

  it('should be defined', () => {
    expect(coffeesController).toBeDefined();
  });

  describe('findAll', () => {
    it('should return an array of coffees', async () => {
      const paginationQuery: PaginationQueryDto = { limit: 0, offset: 0 };
      const coffees: any[] = [];

      vi.spyOn(coffeesService, 'findAll').mockResolvedValue(coffees);

      expect(await coffeesController.findAll(paginationQuery)).toBe(coffees);
    });
  });

  describe('findOne', () => {
    it('should return a coffee by ID', async () => {
      const coffeeId = 1;
      const coffee: any = {};

      vi.spyOn(coffeesService, 'findOne').mockResolvedValue(coffee);

      expect(await coffeesController.findOne(coffeeId)).toBe(coffee);
    });
  });
});
