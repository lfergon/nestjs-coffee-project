import { Module, DynamicModule } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { generateAIStrideModel } from './threat-modelling';
import { Command } from 'commander';

// Import the Model type from Anthropic SDK
import Anthropic from '@anthropic-ai/sdk';
type ClaudeModel =
  | 'claude-3-7-sonnet-20250219'
  | 'claude-3-5-haiku-latest'
  | 'claude-3-5-haiku-20241022'
  | 'claude-3-5-sonnet-latest'
  | 'claude-3-5-sonnet-20241022'
  | 'claude-3-5-sonnet-20240620';

/**
 * Options for the ThreatModellingModule
 */
export interface ThreatModellingOptions {
  /**
   * Path to store output files. Defaults to project root.
   */
  outputPath?: string;

  /**
   * Should include global threat analysis. Defaults to true.
   */
  includeGlobalThreats?: boolean;

  /**
   * Should include entity threat analysis. Defaults to true.
   */
  includeEntityThreats?: boolean;

  /**
   * Model to use for Claude API. Defaults to claude-3-sonnet-20240229
   */
  claudeModel?: ClaudeModel;
}

/**
 * A NestJS module for STRIDE threat modeling
 */
@Module({})
export class ThreatModellingModule {
  /**
   * Register the ThreatModellingModule with options
   * @param options Configuration options
   * @returns Dynamic module
   */
  static register(options: ThreatModellingOptions = {}): DynamicModule {
    return {
      module: ThreatModellingModule,
      imports: [ConfigModule],
      providers: [
        {
          provide: 'THREAT_MODELLING_OPTIONS',
          useValue: options,
        },
      ],
      exports: [],
    };
  }

  /**
   * Generate a CLI command for triggering threat modeling
   * @param appModule The NestJS app module
   * @returns A commander Command object
   */
  static createCommand(appModule: any) {
    const program = new Command();

    program
      .name('threat-model')
      .description('Generate a STRIDE threat model for a NestJS application')
      .option('-o, --output-path <path>', 'Path to store output files')
      .option('--no-global-threats', 'Skip global threat analysis')
      .option('--no-entity-threats', 'Skip entity threat analysis')
      .option('--claude-model <model>', 'Claude model to use', 'claude-3-7-sonnet-20250219')
      .action(
        async (options: {
          outputPath?: string;
          globalThreats?: boolean;
          entityThreats?: boolean;
          claudeModel?: string;
        }) => {
          console.log('🛡️ Generating STRIDE threat model...');
          try {
            const result = await generateAIStrideModel(appModule, {
              outputPath: options.outputPath,
              includeGlobalThreats: options.globalThreats !== false,
              includeEntityThreats: options.entityThreats !== false,
              claudeModel: options.claudeModel as ClaudeModel,
            });

            console.log(`\n✅ Threat model generation complete!`);
            console.log(`📊 JSON output: ${result.jsonPath}`);
            console.log(`📝 Report: ${result.reportPath}`);
          } catch (error) {
            console.error('❌ Error generating threat model:', error.message);
            process.exit(1);
          }
        },
      );

    return program;
  }
}
