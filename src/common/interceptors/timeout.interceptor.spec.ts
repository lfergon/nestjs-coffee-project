import { TimeoutInterceptor } from './timeout.interceptor';
import { describe, it, expect } from 'vitest';

describe('TimeoutInterceptor', () => {
  it('should be defined', () => {
    expect(new TimeoutInterceptor()).toBeDefined();
  });
});
