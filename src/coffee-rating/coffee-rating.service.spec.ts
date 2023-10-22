import { Test, TestingModule } from '@nestjs/testing';
import { CoffeeRatingService } from './coffee-rating.service';
import { describe, it, expect, beforeEach } from 'vitest';

describe('CoffeeRatingService', () => {
  let service: CoffeeRatingService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [CoffeeRatingService],
    }).compile();

    service = module.get<CoffeeRatingService>(CoffeeRatingService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });
});
