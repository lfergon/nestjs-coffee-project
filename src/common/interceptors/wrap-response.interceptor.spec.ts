import { WrapResponseInterceptor } from './wrap-response.interceptor';
import { describe, it, expect } from 'vitest';

describe('WrapResponseInterceptor', () => {
  it('should be defined', () => {
    expect(new WrapResponseInterceptor()).toBeDefined();
  });
});
