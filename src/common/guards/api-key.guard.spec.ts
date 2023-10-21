import { Test, TestingModule } from '@nestjs/testing';
import { Reflector } from '@nestjs/core';
import { ConfigService } from '@nestjs/config';
import { ExecutionContext } from '@nestjs/common';
import { Request } from 'express';
import { ApiKeyGuard } from './api-key.guard';

describe('ApiKeyGuard', () => {
  let apiKeyGuard: ApiKeyGuard;
  let reflector: Reflector;
  let configService: ConfigService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        ApiKeyGuard,
        Reflector,
        {
          provide: ConfigService,
          useValue: {
            get: jest.fn(),
          },
        },
      ],
    }).compile();

    apiKeyGuard = module.get<ApiKeyGuard>(ApiKeyGuard);
    reflector = module.get<Reflector>(Reflector);
    configService = module.get<ConfigService>(ConfigService);
  });

  it('should be defined', () => {
    expect(apiKeyGuard).toBeDefined();
  });

  it('should return true if the route is marked as public', () => {
    jest.spyOn(reflector, 'get').mockReturnValue(true);

    const context = {
      getHandler: jest.fn(),
      switchToHttp: () => ({
        getRequest: jest.fn(),
      }),
    } as unknown as ExecutionContext;

    expect(apiKeyGuard.canActivate(context)).toBe(true);
  });

  it('should return true if the API key in the request header matches the config', () => {
    jest.spyOn(reflector, 'get').mockReturnValue(false);
    jest.spyOn(configService, 'get').mockReturnValue('your-api-key');

    const request = {
      header: (name: string) => (name === 'Authorization' ? 'your-api-key' : undefined),
    } as Request;

    const context = {
      getHandler: jest.fn(),
      switchToHttp: () => ({
        getRequest: () => request,
      }),
    } as unknown as ExecutionContext;

    expect(apiKeyGuard.canActivate(context)).toBe(true);
  });

  it('should return false if the API key in the request header does not match the config', () => {
    // Mocking the reflector to return false (not marked as public)
    jest.spyOn(reflector, 'get').mockReturnValue(false);

    // Mocking the ConfigService to return the expected API key
    jest.spyOn(configService, 'get').mockReturnValue('your-api-key');

    const request = {
      header: (name: string) =>
        name === 'Authorization' ? 'wrong-api-key' : undefined,
    } as Request;

    const context = {
      getHandler: jest.fn(),
      switchToHttp: () => ({
        getRequest: () => request,
      }),
    } as unknown as ExecutionContext;

    expect(apiKeyGuard.canActivate(context)).toBe(false);
  });
});
