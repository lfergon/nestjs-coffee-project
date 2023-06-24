import { DataSource } from 'typeorm';
import { CoffeeRefactor1687622942789 } from './migrations/1687622942789-CoffeeRefactor';

export default new DataSource({
  type: 'postgres',
  host: 'localhost',
  port: 5432,
  username: 'postgres',
  password: 'postgres',
  database: 'postgres',
  entities: [],
  migrations: [CoffeeRefactor1687622942789],
});
