import { Injectable, NestMiddleware } from '@nestjs/common';

@Injectable()
export class LoggingMiddleware implements NestMiddleware {
  use(req: any, response: any, next: () => void) {
    console.time('Request-response time');
    console.log('Hi from middleware!');

    response.on('finish', () => console.timeEnd('Request-response time'));
    next();
  }
}
