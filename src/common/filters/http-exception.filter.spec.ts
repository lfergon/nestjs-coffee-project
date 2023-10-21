import { HttpExceptionFilter } from './http-exception.filter';
import { describe, it, expect } from 'vitest';

describe('HttpExceptionFilter', () => {
  it('should be defined', () => {
    expect(new HttpExceptionFilter()).toBeDefined();
  });
});
