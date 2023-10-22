import { IsNumber, IsString } from "class-validator";
import { ApiProperty } from '@nestjs/swagger';

export class CreateCoffeeDto {
  @ApiProperty({ description: 'The title of a coffee.' })
  @IsString()
  readonly title: string;
  @ApiProperty({ description: 'The brand of a coffee.' })
  @IsString()
  readonly brand: string;
  @ApiProperty({ description: 'The recommendation scale of a coffee.' })
  @IsNumber()
  readonly recommendations: number;
  @ApiProperty({ example: ['chocolate', 'vanilla'] })
  @IsString({ each: true })
  readonly flavors: string[];
}
