# NestJS STRIDE Threat Modeling Tool

This module provides automated STRIDE threat modeling for NestJS applications using Google AI. It analyzes your application structure, endpoints, and data entities to generate a comprehensive threat model.

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
- Google AI API key (set as environment variable `GOOGLE_API_KEY`)

## Running the Tool

There are two ways to run the threat modeling tool:

### Option 1: With Google AI API (Production Mode)

For comprehensive, dynamic threat analysis, use the Google AI API:

1. Obtain a Google AI API key from Google AI Studio or Google Cloud console

2. Set your API key as an environment variable:
   ```bash
   export GOOGLE_API_KEY=your_api_key_here
   ```
   
3. Run the threat modeling tool:
   ```bash
   npm run threat-model -- --output-path ./reports --google-model gemini-2.0-flash-001
   ```

   Available models include:
   - `gemini-2.0-flash-001` - Fast responses, good balance of speed and quality
   - `gemini-2.0-pro-001` - Higher quality but slower responses
   - `gemini-1.5-pro-latest` - Previous generation model (legacy support)

The tool will make live API calls to Google's AI models and generate unique threat analyses based on your codebase. The analysis quality will vary depending on which model you select.

### Option 2: With Mock Responses (Development Mode)

For development and testing without using API quota or when a key isn't available:

1. Set the mock mode environment variable:
   ```bash
   export USE_MOCK_RESPONSE=true
   ```

2. Run the threat modeling tool:
   ```bash
   npm run threat-model -- --output-path ./reports
   ```

The tool will use pre-defined template responses for each type of analysis without making actual API calls. This is useful for:
- Development and testing
- Demonstrations
- CI/CD pipelines
- Environments without internet access

Mock responses cover all STRIDE categories with standardized threat descriptions.

## Installation

The threat modeling tool is included in this project. To use it:

1. Ensure you have the required dependencies:
   ```bash
   npm install commander dotenv @google/genai @google-ai/generativelanguage
   ```

2. Set your Google API key:
   ```bash
   export GOOGLE_API_KEY=your_api_key_here
   ```
   Or add it to your `.env` file:
   ```
   GOOGLE_API_KEY=your_api_key_here
   ```

## Usage

### Via CLI

Run the threat modeling tool using the provided npm script:

```bash
npm run threat-model
```

Or with options:

```bash
npm run threat-model -- --output-path ./reports --google-model gemini-1.5-pro-latest
```

Available options:
- `--output-path <path>`: Specify where to save the output files
- `--no-global-threats`: Skip global application threat analysis
- `--no-entity-threats`: Skip entity data threat analysis
- `--google-model <model>`: Specify which Google AI model to use (default: 'gemini-1.5-flash-latest')

### Programmatically

You can also use the threat modeling tool in your code:

```typescript
import { generateAIStrideModel } from './threat-modelling';
import { AppModule } from './app.module';
import { ConfigService } from '@nestjs/config';

async function runThreatModel() {
  try {
    // Need to create a ConfigService instance or context to get it
    const configService = new ConfigService();
    
    const result = await generateAIStrideModel(
      AppModule,
      configService,
      {
        outputPath: './reports',
        includeGlobalThreats: true,
        includeEntityThreats: true,
        googleModel: 'gemini-1.5-flash-latest',
      }
    );

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
      googleModel: 'gemini-1.5-flash-latest',
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

1. Editing the prompts in `threat-modelling.ts` - These control what the AI analyzes and how it formats responses
2. Adjusting the report generation in the `generateMarkdownReport` method - To change the output format and organization
3. Changing the threat categorization logic in `parseStrideThreats` - To modify how threats are categorized and prioritized
4. Customizing mock responses in `getMockResponseForPrompt` - For more relevant mock results during development

### Customizing Mock Responses

If you're using mock responses (`USE_MOCK_RESPONSE=true`), you can modify the template responses in the `getMockResponseForPrompt` method to better match your application's specific security concerns:

```typescript
private getMockResponseForPrompt(prompt: string): string {
  // Determine type of prompt
  const hasEndpoint = prompt.includes('Endpoint Path:');
  const hasEntity = prompt.includes('Entity Name:');
  const isGlobal = prompt.includes('Application Overview:');
  
  if (hasEndpoint) {
    // Customize endpoint mock responses here
    return `
## Spoofing
- Threat: Authentication bypass through session manipulation.
  Risk: Medium
  Mitigation: Implement proper JWT-based authentication with short-lived tokens and refresh mechanism.

## Tampering
// ...etc
    `;
  }
  // ...
}
```

You can add more detailed and relevant threats based on your application's architecture and needs.

## License

This tool is covered by the project's license.

---

Built on NestJS with Google AI