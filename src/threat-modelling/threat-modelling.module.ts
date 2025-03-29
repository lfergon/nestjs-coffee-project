import { Module } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { NestFactory } from '@nestjs/core';
import {
  generateAIStrideModel,
  GenerateAIStrideModelOptions,
} from './threat-modelling';
import { Command } from 'commander';

/**
 * A NestJS module for STRIDE threat modeling using Google AI
 */
@Module({})
export class ThreatModellingModule {
  /**
   * Generate a CLI command for triggering threat modeling
   * @param appModule The root NestJS app module (used to create context for ConfigService)
   * @returns A commander Command object
   */
  static createCommand(appModule: any) {
    const program = new Command();

    program
      .name('threat-model')
      .description('Generate a STRIDE threat model for a NestJS application using Google AI')
      .option('-o, --output-path <path>', 'Path to store output files (defaults to project root)')
      .option('--no-global-threats', 'Skip global threat analysis') // Commander makes this options.globalThreats = false
      .option('--no-entity-threats', 'Skip entity threat analysis') // Commander makes this options.entityThreats = false
      // Updated model option
      .option(
        '-m, --google-model <model>',
        'Google AI model to use (e.g., gemini-2.0-flash)',
        // Set a default Google AI model
        process.env.GEMMA_MODEL || 'gemini-2.0-flash' // Default if not set by env var
      )
      // Optional: Add CLI options for other parameters if desired
      // .option('--max-tokens <number>', 'Set max output tokens', parseInt)
      // .option('--temperature <number>', 'Set model temperature', parseFloat)
      .action(
        async (cmdOptions: { // Commander passes options here
          outputPath?: string;
          globalThreats: boolean; // Note: Commander default is true unless --no-* is used
          entityThreats: boolean; // Note: Commander default is true unless --no-* is used
          googleModel: string;
          // maxTokens?: number;
          // temperature?: number;
        }) => {
          let appCtx; // To hold the NestJS application context
          try {
            console.log('🛡️ Initializing Threat Model Generation...');

            // --- Create a temporary context to get ConfigService ---
            // We need this because generateAIStrideModel requires ConfigService
            console.log('   Creating temporary application context to access ConfigService...');
            appCtx = await NestFactory.createApplicationContext(appModule, {
              // Disable logging for the context creation unless needed for debugging
              logger: false, // or ['error', 'warn']
            });
            const configService = appCtx.get(ConfigService);
            console.log('   ConfigService obtained.');

            const generatorOptions: GenerateAIStrideModelOptions = {
              outputPath: cmdOptions.outputPath,
              includeGlobalThreats: cmdOptions.globalThreats,
              includeEntityThreats: cmdOptions.entityThreats,
              googleModel: cmdOptions.googleModel,
              gemmaModel: cmdOptions.googleModel,
            };

            console.log(`   Using Model: ${generatorOptions.gemmaModel}`);
            console.log(`   Output Path: ${generatorOptions.outputPath || process.cwd()}`);
            console.log(`   Include Global Threats: ${generatorOptions.includeGlobalThreats}`);
            console.log(`   Include Entity Threats: ${generatorOptions.includeEntityThreats}`);

            console.log('   Starting AI analysis (this may take some time)...');
            const result = await generateAIStrideModel(
              appModule,
              configService,
              generatorOptions,
            );

            console.log(`\n✅ Threat model generation complete!`);
            console.log(`📊 JSON output: ${result.jsonPath}`);
            console.log(`📝 Report: ${result.reportPath}`);

          } catch (error: any) {
            console.error('\n❌ Error during threat model generation:', error.message);
            if (error.stack) {
              console.error(error.stack);
            }
            process.exit(1); // Exit with error code
          } finally {
            // --- Ensure context is closed ---
            if (appCtx) {
              console.log('\n   Closing temporary application context...');
              await appCtx.close();
              console.log('   Context closed.');
            }
          }
        },
      );

    return program;
  }
}