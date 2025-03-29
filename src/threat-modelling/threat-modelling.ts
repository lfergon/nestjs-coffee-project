import { promises as fs } from 'fs';
import * as path from 'path';
import * as dotenv from 'dotenv';
import { INestApplication } from '@nestjs/common';
import {
  GoogleGenAI, HarmBlockThreshold, HarmCategory, SafetySetting,
} from '@google/genai';
import GenerativeModel from "@google-ai/generativelanguage";
import { ConfigService } from '@nestjs/config'; // Assuming ConfigModule is set up globally or imported

// Load environment variables early
dotenv.config();

// --- Interfaces (remain mostly the same) ---

interface ControllerEndpoint {
  path: string;
  method: string;
  handler: string;
  guards: string[];
  // Consider adding reflected metadata here if needed
  // e.g., roles?: string[]; apiOperationSummary?: string;
  dto?: string; // Simplified DTO detection might be complex
  description?: string; // Can potentially be extracted from @ApiOperation decorator
}

interface ControllerInfo {
  name: string;
  basePath: string; // Added for better path reconstruction
  endpoints: ControllerEndpoint[];
}

interface ModuleInfo {
  name: string;
  controllers: ControllerInfo[];
  providers: string[];
  imports: string[];
  exports: string[];
}

interface ThreatModel {
  assetName: string;
  assetType: 'endpoint' | 'data' | 'process';
  threats: {
    category:
      | 'Spoofing'
      | 'Tampering'
      | 'Repudiation'
      | 'Information Disclosure'
      | 'Denial of Service'
      | 'Elevation of Privilege';
    description: string;
    riskLevel: 'Low' | 'Medium' | 'High' | 'Critical';
    mitigationStrategy: string;
  }[];
}

// --- Refactored StrideModelGenerator Class ---

export class StrideModelGenerator {
  private appStructure: ModuleInfo[] = [];
  private entityDefinitions: Map<string, string> = new Map();
  private threatModels: ThreatModel[] = [];
  private app: any; // Temporary NestJS application instance for reflection

  private readonly genAI?: GoogleGenAI; // Google AI Client

  private readonly options: {
    outputPath: string;
    includeGlobalThreats: boolean;
    includeEntityThreats: boolean;
    gemmaModel: string; // Renamed from claudeModel
    maxOutputTokens: number;
    temperature: number;
    safetySettings: SafetySetting[];
  };

  constructor(
    private readonly projectRoot: string,
    private readonly appModule: any,
    private readonly configService: ConfigService,
    options: {
      outputPath?: string;
      includeGlobalThreats?: boolean;
      includeEntityThreats?: boolean;
      gemmaModel?: string;
      googleModel?: string; // Add googleModel option to match interface
      maxOutputTokens?: number;
      temperature?: number;
      safetySettings?: SafetySetting[];
    } = {},
  ) {
    // --- Define Default Safety Settings ---
    const defaultSafetySettings: SafetySetting[] = [
      { category: HarmCategory.HARM_CATEGORY_HARASSMENT, threshold: HarmBlockThreshold.BLOCK_MEDIUM_AND_ABOVE },
      { category: HarmCategory.HARM_CATEGORY_HATE_SPEECH, threshold: HarmBlockThreshold.BLOCK_MEDIUM_AND_ABOVE },
      { category: HarmCategory.HARM_CATEGORY_SEXUALLY_EXPLICIT, threshold: HarmBlockThreshold.BLOCK_MEDIUM_AND_ABOVE },
      { category: HarmCategory.HARM_CATEGORY_DANGEROUS_CONTENT, threshold: HarmBlockThreshold.BLOCK_MEDIUM_AND_ABOVE },
    ];

    // --- Initialize Options ---
    // Check if configService has get method before using it
    const getConfigValue = <T>(key: string, defaultValue: T): T => {
      if (this.configService && typeof this.configService.get === 'function') {
        return this.configService.get<T>(key, defaultValue);
      }
      // If ConfigService doesn't work as expected, try process.env directly
      if (key in process.env) {
        const value = process.env[key];
        // Simple type conversion based on defaultValue
        if (typeof defaultValue === 'number') {
          return Number(value) as unknown as T;
        }
        return value as unknown as T;
      }
      return defaultValue;
    };

    this.options = {
      outputPath: options.outputPath || this.projectRoot,
      includeGlobalThreats: options.includeGlobalThreats !== false,
      includeEntityThreats: options.includeEntityThreats !== false,
      gemmaModel: options.gemmaModel || options.googleModel || getConfigValue<string>('GEMMA_MODEL', 'gemini-2.0-flash-001'), // Support both option names
      maxOutputTokens: options.maxOutputTokens || getConfigValue<number>('GEMMA_MAX_TOKENS', 8192), // Increased default based on newer models
      temperature: options.temperature || getConfigValue<number>('GEMMA_TEMPERATURE', 0.7),
      safetySettings: options.safetySettings || defaultSafetySettings,
    };

    // --- Initialize Google AI Client IN CONSTRUCTOR ---
    console.log('DEBUG: Getting API key...');
    // Try multiple ways to get the API key
    let apiKey: string | undefined;
    
    // First try ConfigService if it has a get method
    if (this.configService && typeof this.configService.get === 'function') {
      try {
        apiKey = this.configService.get<string>('GOOGLE_API_KEY');
        console.log('DEBUG: Retrieved API key from ConfigService');
      } catch (error) {
        console.warn('DEBUG: Error accessing ConfigService.get(): ', error.message);
      }
    }
    
    // Then try process.env directly as fallback
    if (!apiKey && process.env.GOOGLE_API_KEY) {
      apiKey = process.env.GOOGLE_API_KEY;
      console.log('DEBUG: Retrieved API key from process.env');
    }
    
    if (!apiKey) {
      console.error('DEBUG: GOOGLE_API_KEY not found in ConfigService or environment variables');
      throw new Error(
        'GOOGLE_API_KEY environment variable is not set or accessible. ThreatModelGenerator cannot be initialized.',
      );
    }
    console.log('DEBUG: API key retrieved successfully');

    try {
      console.log('DEBUG: Initializing GoogleGenAI client...');
      // Use the correct instantiation for @google/genai
      this.genAI = new GoogleGenAI({ apiKey });
      console.log('DEBUG: GoogleGenAI client initialized successfully');
    } catch (error: any) {
      console.error(`Failed to initialize GoogleGenAI client: ${error.message}`);
      throw new Error(`Failed to initialize GoogleGenAI client: ${error.message}`);
    }

    console.log(`✅ Initialized GoogleGenAI client (model '${this.options.gemmaModel}' will be used).`);
  }

  async generateThreatModel(): Promise<void> {
    try {
      // ** NO AI Client/Model Initialization Here **
      console.log('DEBUG: Starting generateThreatModel');

      console.log('📊 Analyzing NestJS application structure...');
      try {
        await this.analyzeProjectStructure();
        console.log('DEBUG: analyzeProjectStructure completed successfully');
      } catch (error) {
        console.error('DEBUG: Error in analyzeProjectStructure:', error);
        throw error; // Re-throw to be caught by the main catch block
      }

      console.log('🔍 Extracting entity definitions...');
      await this.extractEntityDefinitions();

      const hasEndpoints = this.appStructure.some(m => m.controllers.some(c => c.endpoints.length > 0));
      const hasEntities = this.entityDefinitions.size > 0;

      if (!hasEndpoints && !hasEntities && !this.options.includeGlobalThreats) {
        console.warn("⚠️ No endpoints or entities found, and global analysis is disabled. Skipping AI threat generation.");
      } else {
        console.log(`🤖 Generating AI-based STRIDE threat models using Google AI (${this.options.gemmaModel})...`);
        await this.generateAIThreatModels(); // Calls helpers using callGenerativeAI

        if (this.options.includeGlobalThreats) {
          console.log('🌐 Generating global application threat analysis...');
          await this.generateGlobalThreatAnalysis(); // Uses callGenerativeAI
        }

        if (this.threatModels.length > 0) {
          console.log('📝 Writing threat model files...');
          await this.writeThreatModelToFile();
          await this.generateMarkdownReport();
        } else {
          console.log('ℹ️ No threats were identified or generated. Skipping file writing.');
        }
      }

      console.log('✅ STRIDE threat model generation process finished!');

    } catch (error) {
      console.error('❌ Error during the threat model generation process:', error);
      throw error;
    } finally {
      // Close the app if we created one
      if (this.app) {
        try { 
          this.app.close && this.app.close(); 
        } catch (err) {
          // Ignore errors when closing
        }
        this.app = undefined;
      }
    }
  }


  /**
   * Analyzes the NestJS project structure.
   * This is a simplified implementation that skips complicated reflection
   * and directly scans controller files in the filesystem.
   */
  private async analyzeProjectStructure(): Promise<void> {
    console.log('DEBUG: Starting simple project structure analysis...');
    
    try {
      // Initialize an empty application structure
      this.appStructure = [];
      
      // Use file scanning to find controllers
      console.log('DEBUG: Using file system scanning to detect controllers...');
      const controllers = await this.findControllersByPattern();
      
      // Create a simple app structure with the detected controllers
      this.appStructure = [{
        name: 'AppModule',
        controllers: controllers,
        providers: ['AppService', 'CoffeesService'], // Basic providers
        imports: [],
        exports: []
      }];
      
      if (controllers.length === 0) {
        // If no controllers found, add a fallback
        this.appStructure[0].controllers.push({
          name: 'FallbackController',
          basePath: '/',
          endpoints: [{
            path: '/',
            method: 'GET',
            handler: 'index',
            guards: [],
            description: 'Fallback endpoint'
          }]
        });
      }
      
      // Log statistics
      const totalControllers = this.appStructure.reduce(
        (sum, module) => sum + module.controllers.length, 0
      );
      
      const totalEndpoints = this.appStructure.reduce(
        (sum, module) => sum + module.controllers.reduce(
          (sum2, controller) => sum2 + controller.endpoints.length, 0
        ), 0
      );
      
      console.log(`DEBUG: Analysis complete. Found ${this.appStructure.length} modules, ${totalControllers} controllers, ${totalEndpoints} endpoints`);
      
    } catch (error: any) {
      console.error(`ERROR in analyzeProjectStructure: ${error.message}`);
      console.error(error.stack);
      
      // Fallback to a basic structure in case of failure
      console.warn('WARNING: Error during analysis. Creating fallback structure...');
      
      this.appStructure = [{
        name: 'FallbackAppModule',
        controllers: [{
          name: 'FallbackController',
          basePath: '/',
          endpoints: [{
            path: '/',
            method: 'GET',
            handler: 'index',
            guards: [],
            description: 'Fallback endpoint (error during analysis)'
          }]
        }],
        providers: ['ErrorDetected'],
        imports: [],
        exports: []
      }];
    }
  }
  
  /**
   * Fallback method to find controllers by pattern matching on source files
   * Used if reflection doesn't yield good results
   */
  private async findControllersByPattern(): Promise<ControllerInfo[]> {
    try {
      const controllers: ControllerInfo[] = [];
      
      // Find controller files in src directory
      const controllerFiles = await this.findFilesByPattern(
        path.join(this.projectRoot, 'src'), 
        '.controller.ts'
      );
      
      for (const filePath of controllerFiles) {
        try {
          const content = await fs.readFile(filePath, 'utf8');
          const fileName = path.basename(filePath);
          
          // Extract controller name
          const controllerNameMatch = content.match(/@Controller\(['"]?(.*?)['"]?\)/);
          const controllerName = fileName.replace('.controller.ts', '');
          const basePath = controllerNameMatch ? 
            (controllerNameMatch[1] || '/') : 
            `/${controllerName}`;
          
          // Extract endpoints
          const endpoints: ControllerEndpoint[] = [];
          
          // Match HTTP method decorators: @Get(), @Post(), etc.
          const methodRegex = /@(Get|Post|Put|Delete|Patch|All)\(['"]?(.*?)['"]?\)/g;
          let match;
          
          while ((match = methodRegex.exec(content)) !== null) {
            const httpMethod = match[1].toUpperCase();
            const path = match[2] || '/';
            
            // Find the method name (function after the decorator)
            const methodNameMatch = content.substring(match.index).match(/\s+(\w+)\s*\(/);
            if (methodNameMatch) {
              endpoints.push({
                path: `${basePath}/${path}`.replace(/\/\//g, '/'),
                method: httpMethod,
                handler: methodNameMatch[1],
                guards: [],
                description: `${httpMethod} ${basePath}/${path}`.replace(/\/\//g, '/')
              });
            }
          }
          
          if (endpoints.length > 0) {
            controllers.push({
              name: `${controllerName.charAt(0).toUpperCase()}${controllerName.slice(1)}Controller`,
              basePath: basePath,
              endpoints: endpoints
            });
          }
          
        } catch (error) {
          console.warn(`Could not analyze controller file: ${filePath}`);
        }
      }
      
      return controllers;
      
    } catch (error) {
      console.error('Error in fallback controller detection:', error);
      return [];
    }
  }
  
  /**
   * Helper to find files by extension pattern
   */
  private async findFilesByPattern(dir: string, pattern: string): Promise<string[]> {
    let files: string[] = [];
    try {
      const entries = await fs.readdir(dir, { withFileTypes: true });
      
      for (const entry of entries) {
        const fullPath = path.join(dir, entry.name);
        
        if (entry.isDirectory()) {
          if (entry.name !== 'node_modules' && entry.name !== 'dist' && !entry.name.startsWith('.')) {
            const nestedFiles = await this.findFilesByPattern(fullPath, pattern);
            files = files.concat(nestedFiles);
          }
        } else if (entry.isFile() && entry.name.endsWith(pattern)) {
          files.push(fullPath);
        }
      }
    } catch (error) {
      console.warn(`Error reading directory ${dir}`);
    }
    
    return files;
  }

  // Helper to get HTTP method using NestJS metadata
  private getHttpMethodFromMetadata(handler: Function): string {
    // Check for common decorators' metadata keys
    if (Reflect.getMetadata('__method__', handler) !== undefined) {
      // Older Nest versions might use numerical codes
      const methodCode = Reflect.getMetadata('__method__', handler);
      switch (methodCode) {
        case 0: return 'GET';
        case 1: return 'POST';
        case 2: return 'PUT';
        case 3: return 'DELETE';
        case 4: return 'PATCH';
        case 5: return 'ALL';
        case 6: return 'OPTIONS';
        case 7: return 'HEAD';
        default: break; // Fall through to check string metadata
      }
    }
    // Check metadata used by @nestjs/common decorators (e.g., @Get, @Post)
    const method = Reflect.getMetadata('method', handler);
    if (typeof method === 'string') return method.toUpperCase();

    // Fallback or default
    return 'UNKNOWN';
  }


  // --- Entity Extraction (remains the same) ---
  private async extractEntityDefinitions(): Promise<void> {
    // Implementation remains the same as in the original code...
    // ... (findEntityFiles, readFile, set entityDefinitions)
    // Keep the console logs for progress feedback
    try {
      console.log(`📂 Searching for entity files in: ${path.join(this.projectRoot, 'src')}`);
      const entityFiles = await this.findEntityFiles(path.join(this.projectRoot, 'src'));

      for (const entityPath of entityFiles) {
        try {
          const content = await fs.readFile(entityPath, 'utf8');
          const fileName = path.basename(entityPath);
          const entityNameFromFile = fileName.replace('.entity.ts', ''); // Initial guess

          // Extract class name more reliably
          const classNameMatch = content.match(/export\s+class\s+([\w]+)/);
          // Prioritize extracted class name, fallback to filename-derived name
          const entityName = classNameMatch ? classNameMatch[1] : entityNameFromFile;

          if (entityName) { // Ensure we have a name
            this.entityDefinitions.set(entityName, content);
            console.log(`  ✔️ Found entity: ${entityName} (from ${fileName})`);
          } else {
            console.warn(`  ⚠️ Could not determine entity name for file: ${entityPath}`);
          }

        } catch (error: any) {
          console.warn(`  ⚠️ Error reading entity file ${path.basename(entityPath)}: ${error.message}`);
        }
      }
      console.log(`✅ Extracted ${this.entityDefinitions.size} entity definitions.`);

    } catch (error: any) {
      console.warn(`❌ Error during entity definition extraction: ${error.message}`);
    }
  }


  private async findEntityFiles(dir: string): Promise<string[]> {
    // Implementation remains the same as in the original code...
    // ... (recursive readdir, check for .entity.ts, skip node_modules/dist)
    let entityFiles: string[] = [];
    try {
      const entries = await fs.readdir(dir, { withFileTypes: true });

      for (const entry of entries) {
        const fullPath = path.join(dir, entry.name);

        if (entry.isDirectory()) {
          // Skip common exclusion directories
          if (entry.name !== 'node_modules' && entry.name !== 'dist' && !entry.name.startsWith('.')) {
            entityFiles = entityFiles.concat(await this.findEntityFiles(fullPath));
          }
        } else if (entry.isFile() && entry.name.endsWith('.entity.ts')) {
          entityFiles.push(fullPath);
        }
      }
    } catch (error: any) {
      // Log specific directory errors but continue searching other paths
      if (error.code !== 'EACCES' && error.code !== 'ENOENT') { // Ignore permission/not found errors for specific dirs
        console.warn(`⚠️ Error reading directory ${dir}: ${error.message}`);
      }
    }
    return entityFiles;
  }


  // --- AI Threat Model Generation ---

  private async generateAIThreatModels(): Promise<void> {
    // --- Endpoint Analysis ---
    console.log("\n--- Generating Endpoint Threat Models ---");
    const endpointPromises: Promise<ThreatModel | null>[] = [];
    for (const moduleInfo of this.appStructure) {
      for (const controller of moduleInfo.controllers) {
        for (const endpoint of controller.endpoints) {
          endpointPromises.push(this.generateEndpointThreatModel(controller.name, endpoint));
        }
      }
    }
    const endpointResults = await Promise.all(endpointPromises);
    this.threatModels.push(...endpointResults.filter((tm): tm is ThreatModel => tm !== null)); // Add valid models

    // --- Entity Analysis ---
    if (this.options.includeEntityThreats && this.entityDefinitions.size > 0) {
      console.log("\n--- Generating Data Entity Threat Models ---");
      const entityPromises: Promise<ThreatModel | null>[] = [];
      for (const [entityName, entityDef] of this.entityDefinitions.entries()) {
        entityPromises.push(this.generateDataThreatModel(entityName, entityDef));
      }
      const entityResults = await Promise.all(entityPromises);
      this.threatModels.push(...entityResults.filter((tm): tm is ThreatModel => tm !== null)); // Add valid models
    } else if (this.options.includeEntityThreats) {
      console.log("⏩ Skipping Data Entity Threat Models (no entities found or option disabled).")
    }
  }

  // Helper function for making the AI call and handling basic response
  private async callGenerativeAI(prompt: string): Promise<string> {
    // Always use mock responses for now
    if (process.env.USE_MOCK_RESPONSE === 'true') {
      console.log(`  -> Using mock response for the prompt`);
      return this.getMockResponseForPrompt(prompt);
    }
    
    try {
      console.log(`  -> Calling Google AI model: ${this.options.gemmaModel}...`);
      
      // Check for API key
      if (!process.env.GOOGLE_API_KEY) {
        console.error('GOOGLE_API_KEY environment variable is not set.');
        throw new Error('Missing API key. Set the GOOGLE_API_KEY environment variable.');
      }

      // Create a fresh instance of the AI client for each call to avoid any stale state
      const genAI = new GoogleGenAI({ apiKey: process.env.GOOGLE_API_KEY });
      
      // Call the Google AI API using the documented approach
      console.log(`  -> Sending prompt to Google AI (length: ${prompt.length} chars)...`);
      
      try {
        // Use proper API format per the Google GenAI docs
        // Use the API according to the latest docs
        const result = await genAI.models.generateContent({
          model: this.options.gemmaModel,
          contents: prompt,
          // Note: API might have changed, so let's conditionally add these parameters
          ...(this.options.maxOutputTokens ? { maxOutputTokens: this.options.maxOutputTokens } : {}),
          ...(this.options.temperature ? { temperature: this.options.temperature } : {}),
          ...(this.options.safetySettings ? { safetySettings: this.options.safetySettings } : {})
        });
        
        // Extract text response from the result
        const text = result.text;
        
        if (!text || text.trim().length === 0) {
          console.warn('  -> Received empty response from Google AI');
          return "";
        }
        
        console.log(`  -> Received response from Google AI (length: ${text.length} chars)`);
        return text;
      } catch (apiError: any) {
        console.error(`  -> Google AI API error: ${apiError.message}`);
        console.error(`  -> Model used: ${this.options.gemmaModel}`);
        
        // Provide user-friendly error message based on error type
        if (apiError.message.includes('not found') || apiError.message.includes('invalid model')) {
          throw new Error(`Invalid model name: "${this.options.gemmaModel}". Try using "gemini-2.0-flash-001" instead.`);
        } else {
          throw apiError; // Re-throw so outer catch can handle it
        }
      }
      
    } catch (error: any) {
      console.error(`❌ Error in callGenerativeAI: ${error.message}`);
      
      // Helpful error messages based on error type
      if (error.message.includes('API key')) {
        console.error('  -> API key error: Check that your GOOGLE_API_KEY environment variable is set correctly');
      } else if (error.message.includes('rate limit')) {
        console.error('  -> Rate limit exceeded: You may need to wait before making more requests');
      } else if (error.message.includes('model')) {
        console.error(`  -> Model error: The model "${this.options.gemmaModel}" may not be valid or available. Try "gemini-2.0-flash-001" instead.`);
      }
      
      // Provide mock response when requested via environment variable
      if (process.env.USE_MOCK_RESPONSE === 'true') {
        console.log(`  -> Falling back to mock response due to API error...`);
        return this.getMockResponseForPrompt(prompt);
      }
      
      return ""; // Return empty string on failure
    }
  }
  
  /**
   * Generate a mock response based on prompt content
   * Used as a fallback when API calls fail and the USE_MOCK_RESPONSE flag is set
   */
  private getMockResponseForPrompt(prompt: string): string {
    // Determine type of prompt
    const hasEndpoint = prompt.includes('Endpoint Path:');
    const hasEntity = prompt.includes('Entity Name:');
    const isGlobal = prompt.includes('Application Overview:');
    
    if (hasEndpoint) {
      return `
## Spoofing
- Threat: Authentication bypass through session manipulation.
  Risk: Medium
  Mitigation: Implement proper JWT-based authentication with short-lived tokens and refresh mechanism.

## Tampering
- Threat: Malicious modification of request data.
  Risk: High
  Mitigation: Use NestJS ValidationPipe with strict DTOs and whitelist validation.

## Information Disclosure
- Threat: Sensitive data exposure through error messages.
  Risk: Medium
  Mitigation: Implement a global exception filter that sanitizes error details in production.
      `;
    } else if (hasEntity) {
      return `
## Tampering
- Threat: Unauthorized modification of entity data.
  Risk: High
  Mitigation: Implement RBAC using NestJS guards and ensure proper access control checks.

## Information Disclosure
- Threat: Leakage of sensitive entity data.
  Risk: Medium
  Mitigation: Use data transformation via interceptors to filter out sensitive fields.
      `;
    } else if (isGlobal) {
      return `
## Spoofing
- Threat: Inadequate authentication mechanisms.
  Risk: High
  Mitigation: Implement multi-factor authentication and proper session management.

## Denial of Service
- Threat: Lack of rate limiting allows attackers to overwhelm resources.
  Risk: Medium
  Mitigation: Use @nestjs/throttler to implement rate limiting on all endpoints.
      `;
    }
    
    // Default mock response if type cannot be determined
    return `
## Information Disclosure
- Threat: Sensitive information exposure in logs or error messages.
  Risk: Medium
  Mitigation: Implement proper error handling and log sanitization.
    `;
  }

  /**
   * Generate threat model for a specific endpoint using Google AI.
   */
  private async generateEndpointThreatModel(
    controllerName: string,
    endpoint: ControllerEndpoint,
  ): Promise<ThreatModel | null> { // Allow returning null on error/empty response
    console.log(`  🔄 Analyzing Endpoint: ${endpoint.method} ${endpoint.path}`);

    // Combine system instructions with the user prompt for Google AI
    const prompt = `
      System: You are a cybersecurity expert specializing in threat modeling for NestJS applications using the STRIDE framework. Analyze the provided endpoint details thoroughly.
      
      User: Generate a STRIDE threat model (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege) for the following NestJS API endpoint.
      
      Controller: ${controllerName}
      Endpoint Path: ${endpoint.path}
      HTTP Method: ${endpoint.method}
      Authorization/Guards: ${endpoint.guards.length > 0 ? endpoint.guards.join(', ') : 'None specified'}
      ${endpoint.description ? `Description: ${endpoint.description}\n` : ''}
      For each STRIDE category:
      1.  Identify 1-2 specific, realistic threats relevant to this endpoint.
      2.  Assess the risk level for each threat (Low, Medium, High, or Critical).
      3.  Suggest concise, actionable mitigation strategies, focusing on NestJS/TypeScript best practices (e.g., using pipes for validation, helmet for headers, appropriate guards, rate limiting, ORM security features).
      
      Output Format Requirements:
      - Use clear headings for each STRIDE category (e.g., "## Spoofing").
      - Under each heading, list threats using bullet points or numbered lists.
      - For each threat, clearly state:
          - Threat: [Description of the threat]
          - Risk: [Low | Medium | High | Critical]
          - Mitigation: [Specific mitigation strategy]
      
      Example for one category:
      ## Tampering
      - Threat: Malicious user modifies request payload to bypass validation.
        Risk: High
        Mitigation: Implement robust input validation using NestJS ValidationPipe with class-validator decorators on DTOs. Ensure strict type checking.
      - Threat: Data modification in transit via MITM attack.
        Risk: Medium
        Mitigation: Enforce HTTPS for all communication. Consider HSTS headers.
      `;

    const aiResponse = await this.callGenerativeAI(prompt);

    if (!aiResponse || aiResponse.trim().length === 0) {
      console.warn(`  ⚠️ No valid AI response received for endpoint ${endpoint.method} ${endpoint.path}. Skipping.`);
      return null;
    }

    const threats = this.parseStrideThreats(aiResponse);

    if (threats.length === 0) {
      console.log(`  ℹ️ No specific threats parsed from AI response for endpoint ${endpoint.method} ${endpoint.path}.`);
    }


    return {
      assetName: `${endpoint.method} ${endpoint.path}`,
      assetType: 'endpoint',
      threats: threats,
    };
  }

  /**
   * Generate threat model for a data entity using Google AI.
   */
  private async generateDataThreatModel(entityName: string, entityDef: string): Promise<ThreatModel | null> {
    console.log(`  🔄 Analyzing Entity: ${entityName}`);

    // Limit entity definition length if necessary to avoid exceeding token limits
    const maxDefLength = 2000; // Adjust as needed
    const truncatedEntityDef = entityDef.length > maxDefLength
      ? entityDef.substring(0, maxDefLength) + "\n... (truncated)"
      : entityDef;

    const prompt = `
      System: You are a cybersecurity expert specializing in data security and threat modeling for NestJS applications using the STRIDE framework. Analyze the provided TypeScript entity definition.
      
      User: Generate a STRIDE threat model focusing on data security risks for the following TypeScript entity definition from a NestJS application.
      
      Entity Name: ${entityName}
      Entity Definition (TypeScript):
      \`\`\`typescript
      ${truncatedEntityDef}
      \`\`\`
      
      For each STRIDE category (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege):
      1.  Identify 1-2 specific threats related to the *data* represented by this entity (e.g., unauthorized access, modification, exposure, deletion, privacy violations). Consider how this data might be stored, processed, and transmitted.
      2.  Assess the risk level for each threat (Low, Medium, High, or Critical).
      3.  Suggest concise, actionable mitigation strategies relevant to data protection (e.g., encryption at rest/transit, access controls, ORM security features, data masking, proper logging, input validation where data is set).
      
      Output Format Requirements:
      - Use clear headings for each STRIDE category (e.g., "## Information Disclosure").
      - Under each heading, list threats using bullet points or numbered lists.
      - For each threat, clearly state:
          - Threat: [Description of the threat]
          - Risk: [Low | Medium | High | Critical]
          - Mitigation: [Specific mitigation strategy]
      `;

    const aiResponse = await this.callGenerativeAI(prompt);

    if (!aiResponse || aiResponse.trim().length === 0) {
      console.warn(`  ⚠️ No valid AI response received for entity ${entityName}. Skipping.`);
      return null;
    }

    const threats = this.parseStrideThreats(aiResponse);

    if (threats.length === 0) {
      console.log(`  ℹ️ No specific threats parsed from AI response for entity ${entityName}.`);
    }

    return {
      assetName: entityName,
      assetType: 'data',
      threats: threats,
    };
  }

  /**
   * Generate a global application security assessment using Google AI.
   */
  private async generateGlobalThreatAnalysis(): Promise<void> {
    try {
      const applicationSummary = {
        controllers: this.appStructure.flatMap((m) => m.controllers.map((c) => c.name)),
        endpoints: this.appStructure.flatMap((m) =>
          m.controllers.flatMap((c) =>
            c.endpoints.map((e) => `${e.method} ${e.path}`),
          ),
        ),
        entities: Array.from(this.entityDefinitions.keys()),
        modules: this.appStructure.map((m) => m.name),
      };

      console.log(`🔄 Generating global application threat assessment`);

      const prompt = `
        System: You are a cybersecurity expert specializing in architectural security reviews and threat modeling for NestJS applications using the STRIDE framework.
        
        User: Perform a high-level, architecture-focused STRIDE threat model analysis for a NestJS application with the following components:
        
        Application Overview:
        - Modules: ${applicationSummary.modules.join(', ') || 'N/A'}
        - Controllers: ${applicationSummary.controllers.join(', ') || 'N/A'}
        - Total Endpoints Found: ${applicationSummary.endpoints.length}
        - Data Entities Found: ${applicationSummary.entities.join(', ') || 'N/A'}
        
        Focus on potential application-wide or architectural security weaknesses across these STRIDE categories: Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege.
        
        Consider common NestJS patterns and potential pitfalls related to:
        1.  Authentication & Authorization (e.g., JWT handling, guard implementation, session management)
        2.  Dependency Management (vulnerable libraries)
        3.  Configuration Security (secrets management)
        4.  Input Validation (consistency across application)
        5.  Error Handling & Information Leakage (stack traces)
        6.  Logging & Monitoring (sufficiency for security events)
        7.  Rate Limiting & Resource Management
        8.  Middleware Security (e.g., Helmet, CORS)
        
        For each STRIDE category:
        1.  Identify 1-2 significant *global* or *architectural* threats.
        2.  Assess the typical risk level (Low, Medium, High, or Critical) for such threats in a generic NestJS app.
        3.  Suggest high-level, actionable mitigation strategies applicable across the application.
        
        Output Format Requirements:
        - Use clear headings for each STRIDE category (e.g., "## Denial of Service").
        - Under each heading, list threats.
        - For each threat, clearly state:
            - Threat: [Description of the architectural threat]
            - Risk: [Low | Medium | High | Critical]
            - Mitigation: [General architectural mitigation strategy]
        `;
      const aiResponse = await this.callGenerativeAI(prompt);

      if (!aiResponse || aiResponse.trim().length === 0) {
        console.warn(`⚠️ No valid AI response received for global analysis. Skipping.`);
        return;
      }


      const threats = this.parseStrideThreats(aiResponse);

      if (threats.length === 0) {
        console.log(`ℹ️ No specific threats parsed from AI response for global analysis.`);
        return; // Don't add an empty model
      }

      const globalThreatModel: ThreatModel = {
        assetName: 'Global Application Architecture',
        assetType: 'process',
        threats: threats,
      };

      this.threatModels.push(globalThreatModel);
      console.log(`✅ Global threat analysis added.`);

    } catch (error: any) {
      console.warn(`⚠️ Error generating global threat analysis: ${error.message}`);
    }
  }


  /**
   * Parses STRIDE threats from the structured AI response text.
   * This relies heavily on the AI following the requested format.
   * Consider asking the AI for JSON output in the future for more robustness.
   */
  private parseStrideThreats(aiResponse: string): ThreatModel['threats'] {
    const parsedThreats: ThreatModel['threats'] = [];
    const threatCategories = [
      'Spoofing', 'Tampering', 'Repudiation',
      'Information Disclosure', 'Denial of Service', 'Elevation of Privilege'
    ];

    // Normalize line endings
    const normalizedResponse = aiResponse.replace(/\r\n/g, '\n');

    // Split into potential category blocks
    // Improved regex that handles different markdown heading formats and titles
    const categoryRegex = /(?:^|\n)(?:#+|\*\*)\s*([^\n*#]+?)(?:\*\*)?\s*(?:\n|:)([\s\S]*?)(?=\n(?:#+|\*\*)\s|$)/g;
    let match;

    while ((match = categoryRegex.exec(normalizedResponse)) !== null) {
      const categoryName = match[1].trim();
      const categoryContent = match[2].trim();

      // Find the matching STRIDE category (more flexible case-insensitive check)
      // This allows for variations like "Spoofing attacks", "Spoofing threats", etc.
      let strideCategory = undefined;
      for (const cat of threatCategories) {
        if (
          categoryName.toLowerCase().includes(cat.toLowerCase()) || 
          // Special case for Information Disclosure which might be referred to as just "Information"
          (cat === 'Information Disclosure' && categoryName.toLowerCase().includes('information'))
        ) {
          strideCategory = cat as ThreatModel['threats'][0]['category'];
          break;
        }
      }

      if (strideCategory) {
        // Need to parse Risk and Mitigation within the threat block
        const riskRegex = /Risk:\s*(Low|Medium|High|Critical)/i;
        const mitigationRegex = /Mitigation:\s*([\s\S]*?)(?=\n\s*[-\*\d]+\.?\s*Threat:|\n##\s|$)/i;


        // Make a more flexible pattern to extract threat blocks
        // This handles different formatting styles that the AI might use
        const threatBlocks = categoryContent.split(/(?=\n\s*[-\*\d]+\.?\s*(?:Threat|Description):)/gi);

        // If we can't find any threat blocks with the above pattern, try an alternative approach
        let blocksToProcess = threatBlocks;
        if (threatBlocks.length <= 1 && categoryContent.length > 50) {
          // Alternative: try to split by bullet points or numbered items
          const altBlocks = categoryContent.split(/(?=\n\s*[-\*\d]+\.?\s*)/g);
          if (altBlocks.length > 1) {
            blocksToProcess = altBlocks;
          }
        }

        for(const block of blocksToProcess) {
          if (block.trim().length < 10) continue; // Skip empty blocks

          // More flexible threat description extraction
          // Try different possible labels the AI might use
          const threatLabels = ['Threat:', 'Description:', 'Issue:'];
          let description = '';
          let threatDescriptionMatch = null;
          
          for (const label of threatLabels) {
            const regex = new RegExp(`${label}\\s*([\\s\\S]*?)(?=\\n\\s*Risk:|\\n\\s*Mitigation:|\\n##|$)`, 'i');
            threatDescriptionMatch = block.match(regex);
            if (threatDescriptionMatch && threatDescriptionMatch[1].trim()) {
              description = threatDescriptionMatch[1].trim();
              break;
            }
          }
          
          // If still no match, try to use the first line as description
          if (!description && block.trim()) {
            // Use the first line or sentence as the description
            const firstLine = block.split(/\n/)[0].trim();
            if (firstLine && firstLine.length > 10 && !firstLine.match(/^[-\*\d]+\.?\s*$/)) {
              description = firstLine;
            }
          }
          const riskMatch = block.match(riskRegex);
          const mitigationMatch = block.match(mitigationRegex);


          // If we found a description (through any method above), process the threat
          if (description) {
            // Determine risk level
            const riskLevel = riskMatch ? riskMatch[1] as ThreatModel['threats'][0]['riskLevel'] : 'Medium'; // Default to Medium if not found
            // Extract mitigation
            const mitigationStrategy = mitigationMatch ? mitigationMatch[1].trim() : 'Mitigation strategy not specified.';

            if (description.length > 5) { // Basic sanity check
              parsedThreats.push({
                category: strideCategory,
                description: description,
                riskLevel: riskLevel,
                mitigationStrategy: mitigationStrategy,
              });
            }
          }
        }

      } else {
        console.warn(`⚠️ Found section heading "${categoryName}" in AI response that doesn't match a known STRIDE category.`);
      }
    }


    if (parsedThreats.length === 0 && aiResponse.trim().length > 0) {
      console.warn("⚠️ AI response received, but failed to parse any structured STRIDE threats. The AI might not have followed the requested format. Raw response snippet:", aiResponse.substring(0, 300) + "...");
      // Could potentially add the raw response as a single 'process' threat for manual review
    }


    return parsedThreats;
  }


  // --- File Writing (JSON and Markdown Report) ---
  private async writeThreatModelToFile(): Promise<void> {
    // Ensure output directory exists
    const outputDir = this.options.outputPath;
    await fs.mkdir(outputDir, { recursive: true });


    const outputFile = path.join(outputDir, 'threat-model.json');
    try {
      await fs.writeFile(outputFile, JSON.stringify(this.threatModels, null, 2), 'utf8');
      console.log(`✅ Threat model JSON written to ${outputFile}`);
    } catch (error: any) {
      console.error(`❌ Error writing threat model JSON to ${outputFile}: ${error.message}`);
      throw error; // Re-throw if writing fails
    }
  }


  private async generateMarkdownReport(): Promise<void> {
    // Ensure output directory exists
    const outputDir = this.options.outputPath;
    await fs.mkdir(outputDir, { recursive: true });


    const reportFile = path.join(outputDir, 'threat-model-report.md');
    // --- Markdown Generation Logic ---
    // This extensive logic remains largely the same as in your original code.
    // It iterates through `this.threatModels` to build the report.
    // No changes needed here unless you want to alter the report structure.
    // ... (Keep the existing markdown generation logic from the original code) ...
    console.log("📝 Generating Markdown report...");


    // (Paste the entire generateMarkdownReport method content from your original code here)
    // ... it's quite long, so just indicating to reuse it ...
    let markdownContent = `# NestJS Application STRIDE Threat Model\n\n`;
    markdownContent += `*Generated on ${new Date().toLocaleString()} using Google AI (${this.options.gemmaModel})*\n\n`;


    // Calculate statistics
    const totalThreats = this.threatModels.reduce((acc, tm) => acc + tm.threats.length, 0);
    if (totalThreats === 0) {
      markdownContent += "## Executive Summary\n\n";
      markdownContent += "No threats were identified or parsed from the analysis. This could be due to:\n";
      markdownContent += "- The application structure having no analyzable components.\n";
      markdownContent += "- Errors during the AI analysis phase.\n";
      markdownContent += "- The AI not responding in the expected format.\n\n";
      markdownContent += "Please review the console logs for more details.\n";


      try {
        await fs.writeFile(reportFile, markdownContent, 'utf8');
        console.log(`✅ Empty threat model report written to ${reportFile}`);
      } catch (error: any) {
        console.error(`❌ Error writing empty threat model report to ${reportFile}: ${error.message}`);
        throw error;
      }
      return; // Exit early if no threats
    }


    const allThreatDetails = this.threatModels.flatMap((tm) =>
      tm.threats.map((t) => ({
        asset: tm.assetName,
        assetType: tm.assetType,
        category: t.category,
        description: t.description,
        riskLevel: t.riskLevel,
        mitigationStrategy: t.mitigationStrategy,
      }))
    );


    const criticalThreats = allThreatDetails.filter((t) => t.riskLevel === 'Critical');
    const highThreats = allThreatDetails.filter((t) => t.riskLevel === 'High');
    const mediumThreats = allThreatDetails.filter((t) => t.riskLevel === 'Medium');
    const lowThreats = allThreatDetails.filter((t) => t.riskLevel === 'Low');


    // Calculate percentages safely (avoid division by zero)
    const criticalPercentage = totalThreats > 0 ? ((criticalThreats.length / totalThreats) * 100).toFixed(1) : '0.0';
    const highPercentage = totalThreats > 0 ? ((highThreats.length / totalThreats) * 100).toFixed(1) : '0.0';
    const mediumPercentage = totalThreats > 0 ? ((mediumThreats.length / totalThreats) * 100).toFixed(1) : '0.0';
    const lowPercentage = totalThreats > 0 ? ((lowThreats.length / totalThreats) * 100).toFixed(1) : '0.0';


    // Executive Summary
    markdownContent += `## Executive Summary\n\n`;
    markdownContent += `This report presents a STRIDE threat model analysis of the NestJS application, generated with the assistance of Google AI. `;
    markdownContent += `The analysis identified **${totalThreats} potential security threats** across analyzed endpoints, data entities, and the application architecture.\n\n`;


    // Risk Distribution
    markdownContent += `### Risk Level Distribution\n`;
    markdownContent += `- **Critical**: ${criticalThreats.length} threats (${criticalPercentage}%)\n`;
    markdownContent += `- **High**: ${highThreats.length} threats (${highPercentage}%)\n`;
    markdownContent += `- **Medium**: ${mediumThreats.length} threats (${mediumPercentage}%)\n`;
    markdownContent += `- **Low**: ${lowThreats.length} threats (${lowPercentage}%)\n\n`;


    // Asset Analysis
    const endpointCount = this.threatModels.filter((tm) => tm.assetType === 'endpoint').length;
    const dataEntityCount = this.threatModels.filter((tm) => tm.assetType === 'data').length;
    const processCount = this.threatModels.filter((tm) => tm.assetType === 'process').length;


    markdownContent += `### Asset Analysis Summary\n`;
    markdownContent += `- **Total Assets Analyzed**: ${this.threatModels.length}\n`;
    if (endpointCount > 0) markdownContent += `- **Endpoints Analyzed**: ${endpointCount}\n`;
    if (dataEntityCount > 0) markdownContent += `- **Data Entities Analyzed**: ${dataEntityCount}\n`;
    if (processCount > 0) markdownContent += `- **Process/Architecture Elements Analyzed**: ${processCount}\n`;
    markdownContent += `\n`;


    // Top Threat Categories Analysis
    const threatCategoryCount = new Map<string, number>();
    allThreatDetails.forEach((threat) => {
      const currentCount = threatCategoryCount.get(threat.category) || 0;
      threatCategoryCount.set(threat.category, currentCount + 1);
    });


    const sortedCategories = Array.from(threatCategoryCount.entries())
      .sort((a, b) => b[1] - a[1]) // Sort descending by count
      .slice(0, 5); // Show top 5


    if (sortedCategories.length > 0) {
      markdownContent += `### Top ${sortedCategories.length} Threat Categories by Frequency\n`;
      sortedCategories.forEach(([category, count], index) => {
        markdownContent += `${index + 1}. **${category}**: ${count} threats identified\n`;
      });
      markdownContent += `\n`;
    }


    // --- Detailed Sections (Critical, High, Endpoints, Data, Global Recommendations, Timeline) ---
    // (Paste the rest of the detailed markdown generation logic from your original code here)
    // Make sure it uses the `allThreatDetails`, `criticalThreats`, `highThreats`, etc. variables defined above.


    // Critical Vulnerabilities Section
    if (criticalThreats.length > 0) {
      markdownContent += `## Critical Vulnerabilities (Immediate Attention Required)\n\n`;
      criticalThreats.forEach((threat, index) => {
        markdownContent += `### ${index + 1}. ${threat.category} in ${threat.asset} (${threat.assetType})\n`;
        markdownContent += `**Risk**: Critical\n`;
        markdownContent += `**Description**: ${threat.description}\n`;
        markdownContent += `**Mitigation**: ${threat.mitigationStrategy}\n\n`;
      });
    }


    // High-Risk Vulnerabilities Section
    if (highThreats.length > 0) {
      markdownContent += `## High-Risk Vulnerabilities\n\n`;
      // Group high threats by category for better readability
      const categorizedHighThreats = highThreats.reduce(
        (acc, threat) => {
          const category = threat.category;
          if (!acc[category]) acc[category] = [];
          acc[category].push(threat);
          return acc;
        },
        {} as Record<string, typeof highThreats>
      );


      Object.entries(categorizedHighThreats).forEach(([category, threatsInCategory]) => {
        markdownContent += `### ${category}\n`;
        threatsInCategory.forEach((threat, index) => {
          markdownContent += `${index + 1}. **Asset**: ${threat.asset} (${threat.assetType})\n`;
          markdownContent += `   **Description**: ${threat.description}\n`;
          markdownContent += `   **Mitigation**: ${threat.mitigationStrategy}\n\n`;
        });
      });
    }


    // Endpoint Analysis Section (Focus on High/Critical)
    const endpointModels = this.threatModels.filter((tm) => tm.assetType === 'endpoint');
    if (endpointModels.length > 0) {
      markdownContent += `## API Endpoint Security Highlights\n\n`;
      const endpointsWithHighCritical = endpointModels
        .map(model => ({
          ...model,
          criticalCount: model.threats.filter(t => t.riskLevel === 'Critical').length,
          highCount: model.threats.filter(t => t.riskLevel === 'High').length,
        }))
        .filter(model => model.criticalCount > 0 || model.highCount > 0)
        .sort((a, b) => (b.criticalCount * 2 + b.highCount) - (a.criticalCount * 2 + a.highCount)); // Prioritize critical


      if (endpointsWithHighCritical.length > 0) {
        markdownContent += `### Endpoints with Critical or High Risks\n\n`;
        endpointsWithHighCritical.slice(0, 10).forEach((ep) => { // Show top 10 or fewer
          markdownContent += `#### ${ep.assetName}\n`;
          markdownContent += `(${ep.criticalCount} Critical, ${ep.highCount} High Risks)\n\n`;


          ep.threats.filter(t => t.riskLevel === 'Critical' || t.riskLevel === 'High')
            .forEach(threat => {
              markdownContent += `- **[${threat.riskLevel}] ${threat.category}**: ${threat.description}\n`;
              markdownContent += `  - **Mitigation**: ${threat.mitigationStrategy}\n`;
            });
          markdownContent += `\n`;
        });
        if (endpointsWithHighCritical.length > 10) {
          markdownContent += `*... and ${endpointsWithHighCritical.length - 10} more endpoints with critical/high risks.*\n\n`;
        }
      } else {
        markdownContent += `No critical or high-risk threats were identified specifically for the analyzed endpoints.\n\n`;
      }
    }


    // Data Entity Security Analysis (Focus on High/Critical)
    const entityModels = this.threatModels.filter((tm) => tm.assetType === 'data');
    if (entityModels.length > 0) {
      markdownContent += `## Data Entity Security Highlights\n\n`;
      const entitiesWithHighCritical = entityModels
        .map(model => ({
          ...model,
          criticalCount: model.threats.filter(t => t.riskLevel === 'Critical').length,
          highCount: model.threats.filter(t => t.riskLevel === 'High').length,
        }))
        .filter(model => model.criticalCount > 0 || model.highCount > 0)
        .sort((a, b) => (b.criticalCount * 2 + b.highCount) - (a.criticalCount * 2 + a.highCount));


      if (entitiesWithHighCritical.length > 0) {
        markdownContent += `### Entities with Critical or High Risks\n\n`;
        entitiesWithHighCritical.forEach((entity) => {
          markdownContent += `#### ${entity.assetName}\n`;
          markdownContent += `(${entity.criticalCount} Critical, ${entity.highCount} High Risks)\n\n`;


          entity.threats.filter(t => t.riskLevel === 'Critical' || t.riskLevel === 'High')
            .forEach(threat => {
              markdownContent += `- **[${threat.riskLevel}] ${threat.category}**: ${threat.description}\n`;
              markdownContent += `  - **Mitigation**: ${threat.mitigationStrategy}\n`;
            });
          markdownContent += `\n`;
        });
      } else {
        markdownContent += `No critical or high-risk threats were identified specifically for the analyzed data entities.\n\n`;
      }
    }


    // Global Security Recommendations / Cross-Cutting Concerns
    const globalModel = this.threatModels.find(tm => tm.assetType === 'process');
    if (globalModel && globalModel.threats.length > 0) {
      markdownContent += `## Global & Architectural Recommendations\n\n`;
      globalModel.threats
        .sort((a, b) => { // Sort by risk level within global
          const riskOrder = { Critical: 4, High: 3, Medium: 2, Low: 1 };
          return (riskOrder[b.riskLevel] || 0) - (riskOrder[a.riskLevel] || 0);
        })
        .forEach(threat => {
          markdownContent += `### ${threat.category} - [${threat.riskLevel}]\n`;
          markdownContent += `**Threat**: ${threat.description}\n`;
          markdownContent += `**Mitigation**: ${threat.mitigationStrategy}\n\n`;
        });


    } else {
      // Add generic recommendations if no global analysis was done or yielded results
      markdownContent += `## General Security Recommendations\n\n`;
      markdownContent += `- **Authentication & Authorization**: Ensure robust mechanisms (e.g., JWT with refresh tokens, RBAC guards) are consistently applied.\n`;
      markdownContent += `- **Input Validation**: Use global ValidationPipes and specific DTOs with validation decorators for all inputs.\n`;
      markdownContent += `- **Security Headers**: Employ Helmet.js or similar middleware for essential security headers (CSP, HSTS, X-Frame-Options, etc.).\n`;
      markdownContent += `- **Rate Limiting**: Implement rate limiting (e.g., using @nestjs/throttler) to prevent abuse and DoS.\n`;
      markdownContent += `- **Error Handling**: Avoid leaking sensitive information or stack traces in error responses. Use exception filters.\n`;
      markdownContent += `- **Dependency Management**: Regularly scan dependencies for known vulnerabilities (e.g., using npm audit or Snyk).\n`;
      markdownContent += `- **Secrets Management**: Use environment variables and a configuration service (@nestjs/config) - never hardcode secrets.\n`;
      markdownContent += `- **Logging**: Implement structured logging that captures relevant security events (auth success/failure, significant errors, access control decisions).\n\n`;
    }


    // Recommended Implementation Timeline (Simplified)
    markdownContent += `## Recommended Prioritization\n\n`;
    markdownContent += `Focus remediation efforts based on risk level:\n\n`;


    if (criticalThreats.length > 0) {
      markdownContent += `### 1. Critical Risks (Address Immediately)\n`;
      markdownContent += `Prioritize fixing all ${criticalThreats.length} critical vulnerabilities identified. These represent the highest potential impact.\n\n`;
      // Optional: List a few examples
      criticalThreats.slice(0,3).forEach(t => markdownContent += `- Example: ${t.category} in ${t.asset} - ${t.mitigationStrategy}\n`);
      if (criticalThreats.length > 3) markdownContent += `- ... and ${criticalThreats.length - 3} more.\n`;
      markdownContent += `\n`;
    }


    if (highThreats.length > 0) {
      markdownContent += `### 2. High Risks (Address Next)\n`;
      markdownContent += `Address the ${highThreats.length} high-risk vulnerabilities following the critical ones. These often involve significant security gaps.\n\n`;
      highThreats.slice(0,3).forEach(t => markdownContent += `- Example: ${t.category} in ${t.asset} - ${t.mitigationStrategy}\n`);
      if (highThreats.length > 3) markdownContent += `- ... and ${highThreats.length - 3} more.\n`;
      markdownContent += `\n`;
    }


    if (mediumThreats.length > 0) {
      markdownContent += `### 3. Medium Risks (Address Systematically)\n`;
      markdownContent += `Plan to address the ${mediumThreats.length} medium-risk vulnerabilities as part of regular development cycles. These often relate to defense-in-depth.\n\n`;
    }


    if (lowThreats.length > 0) {
      markdownContent += `### 4. Low Risks (Address Opportunistically)\n`;
      markdownContent += `Address the ${lowThreats.length} low-risk vulnerabilities when time permits or during related feature work. These are typically minor improvements or hardening measures.\n\n`;
    }


    // Conclusion
    markdownContent += `## Conclusion\n\n`;
    markdownContent += `This AI-assisted STRIDE threat model provides a valuable baseline for understanding potential security risks in the application. It identified ${totalThreats} threats, highlighting ${criticalThreats.length} critical and ${highThreats.length} high-risk issues requiring prompt attention. `;
    markdownContent += `Implementing the recommended mitigations, prioritized by risk level, will significantly enhance the application's security posture. Remember that automated analysis is a starting point; manual review and deeper investigation by the development team are crucial for comprehensive security.\n\n`;


    markdownContent += `---\n\n`;
    markdownContent += `*Report generated automatically using NestJS STRIDE Threat Modeling Tool*\n`;
    markdownContent += `*AI Analysis powered by Google Generative AI (${this.options.gemmaModel})*`;
    // --- End of reused Markdown Logic ---


    try {
      await fs.writeFile(reportFile, markdownContent, 'utf8');
      console.log(`✅ Threat model report written to ${reportFile}`);
    } catch (error: any) {
      console.error(`❌ Error writing threat model report to ${reportFile}: ${error.message}`);
      throw error; // Re-throw if writing fails
    }
  }


} // End of StrideModelGenerator class

// --- Exported Function (Usage Example) ---
export interface GenerateAIStrideModelOptions {
  outputPath?: string;
  includeGlobalThreats?: boolean;
  includeEntityThreats?: boolean;
  gemmaModel?: string;
  googleModel?: string; // Add googleModel option for consistency with ThreatModellingOptions
  maxOutputTokens?: number;
  temperature?: number;
  safetySettings?: SafetySetting[];
}

export interface ThreatModelResult {
  jsonPath: string;
  reportPath: string;
  threatModels: ThreatModel[]; // Also return the parsed models
}

/**
 * Generates a STRIDE threat model for a NestJS application using Google AI.
 *
 * @param appModule The root AppModule of the NestJS application.
 * @param configService An instance of NestJS ConfigService initialized with environment variables (requires GOOGLE_API_KEY).
 * @param options Configuration options for the generation process.
 * @returns Paths to the generated JSON and Markdown files, and the parsed threat models.
 */
export async function generateAIStrideModel(
  appModule: any,
  configService: ConfigService, // Require ConfigService for API key etc.
  options?: GenerateAIStrideModelOptions
): Promise<ThreatModelResult> {
  const projectRoot = process.cwd(); // Or determine project root differently if needed
  // Ensure ConfigService is provided
  if (!configService) {
    throw new Error("ConfigService instance must be provided to generateAIStrideModel.");
  }
  const generator = new StrideModelGenerator(projectRoot, appModule, configService, options);
  await generator.generateThreatModel();
  // Construct absolute paths for return
  const absoluteOutputPath = options?.outputPath
    ? path.resolve(options.outputPath)
    : path.resolve(projectRoot); // Use resolved project root if no output path

  const jsonPath = path.join(absoluteOutputPath, 'threat-model.json');
  const reportPath = path.join(absoluteOutputPath, 'threat-model-report.md');

  // Return paths and the actual data
  return {
    jsonPath: jsonPath,
    reportPath: reportPath,
    // @ts-ignore - Accessing private member for return value, consider a public getter if needed elsewhere
    threatModels: generator.threatModels
  };
}