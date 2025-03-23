# NestJS STRIDE Threat Modeling Tool

This module provides automated STRIDE threat modeling for NestJS applications using Claude AI. It analyzes your application structure, endpoints, and data entities to generate a comprehensive threat model.

## Features

- AI-powered STRIDE threat analysis (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege)
- Analysis of API endpoints and controller methods
- Analysis of entity definitions and data models
- Global application threat assessment
- Comprehensive markdown report generation with prioritized recommendations
- JSON output for programmatic use
- CLI interface for easy execution

## Prerequisites

- Node.js 16 or higher
- NestJS 8 or higher
- Anthropic Claude API key (set as environment variable `ANTHROPIC_API_KEY`)

## Installation

The threat modeling tool is included in this project. To use it:

1. Ensure you have the required dependencies:
   ```bash
   npm install commander dotenv @anthropic-ai/sdk
   ```

2. Set your Anthropic API key:
   ```bash
   export ANTHROPIC_API_KEY=your_api_key_here
   ```
   Or add it to your `.env` file:
   ```
   ANTHROPIC_API_KEY=your_api_key_here
   ```

## Usage

### Via CLI

Run the threat modeling tool using the provided npm script:

```bash
npm run threat-model
```

Or with options:

```bash
npm run threat-model -- --output-path ./reports --claude-model claude-3-haiku-20240307
```

Available options:
- `--output-path <path>`: Specify where to save the output files
- `--no-global-threats`: Skip global application threat analysis
- `--no-entity-threats`: Skip entity data threat analysis
- `--claude-model <model>`: Specify which Claude model to use (default: 'claude-3-7-sonnet-20250219')

### Programmatically

You can also use the threat modeling tool in your code:

```typescript
import { generateAIStrideModel } from './threat-modelling';
import { AppModule } from './app.module';

async function runThreatModel() {
  try {
    const result = await generateAIStrideModel(AppModule, {
      outputPath: './reports',
      includeGlobalThreats: true,
      includeEntityThreats: true,
      claudeModel: 'claude-3-7-sonnet-20250219',
    });

    console.log(`Report generated at: ${result.reportPath}`);
  } catch (error) {
    console.error('Error generating threat model:', error);
  }
}

runThreatModel();
```

### As a Module

You can use the ThreatModellingModule in your NestJS application:

```typescript
import { Module } from '@nestjs/common';
import { ThreatModellingModule } from './threat-modelling';

@Module({
  imports: [
    ThreatModellingModule.register({
      outputPath: './reports',
      includeGlobalThreats: true,
    }),
  ],
})
export class AppModule {}
```

## Output

The tool generates two files:

1. `threat-model.json` - JSON representation of the threat model
2. `threat-model-report.md` - Detailed markdown report with:
   - Executive summary
   - Risk level distribution
   - Critical and high-risk vulnerabilities
   - API endpoint security analysis
   - Data entity security analysis
   - Global security recommendations
   - Implementation timeline

## Customization

You can modify the threat model generation by:

1. Editing the prompts in `threat-modelling.ts`
2. Adjusting the report generation in the `generateMarkdownReport` method
3. Changing the threat categorization logic

## License

This tool is covered by the project's license.

---

Built on NestJS with Claude AI
