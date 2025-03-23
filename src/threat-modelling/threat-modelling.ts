import { promises as fs } from 'fs';
import * as path from 'path';
import { NestFactory } from '@nestjs/core';
import { DiscoveryService, MetadataScanner, ModuleRef } from '@nestjs/core';
import * as dotenv from 'dotenv';
import { INestApplication } from '@nestjs/common';
import Anthropic from '@anthropic-ai/sdk';
import { InstanceWrapper } from '@nestjs/core/injector/instance-wrapper';
import { ConfigService } from '@nestjs/config';

dotenv.config();

// Initialize Anthropic Claude client with API key from environment variables
// This will be replaced with ConfigService in the actual implementation
const initializeClaudeClient = (apiKey: string) => {
  return new Anthropic({
    apiKey,
  });
};

interface ControllerEndpoint {
  path: string;
  method: string;
  handler: string;
  guards: string[];
  dto?: string;
  description?: string;
}

// Define controller structure to fix the type error with endpoints.push
interface ControllerInfo {
  name: string;
  endpoints: ControllerEndpoint[];
}

interface ModuleInfo {
  name: string;
  controllers: {
    name: string;
    endpoints: ControllerEndpoint[];
  }[];
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

class StrideModelGenerator {
  private appStructure: ModuleInfo[] = [];
  private entityDefinitions: Map<string, string> = new Map();
  private threatModels: ThreatModel[] = [];
  private claudeClient: Anthropic;
  private app: INestApplication;

  constructor(
    private readonly projectRoot: string,
    private readonly appModule: any,
    private readonly options: {
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
      claudeModel?: string;
    } = {},
  ) {
    // Set defaults
    this.options = {
      outputPath: options.outputPath || this.projectRoot,
      includeGlobalThreats: options.includeGlobalThreats !== false,
      includeEntityThreats: options.includeEntityThreats !== false,
      claudeModel: options.claudeModel || 'claude-3-7-sonnet-20250219',
    };
  }

  async generateThreatModel(): Promise<void> {
    try {
      // Initialize Claude client from environment variable
      const apiKey = process.env.ANTHROPIC_API_KEY;
      if (!apiKey) {
        throw new Error(
          'ANTHROPIC_API_KEY environment variable is not set. Please set it before running the threat model generator.',
        );
      }
      this.claudeClient = initializeClaudeClient(apiKey);

      console.log('📊 Analyzing NestJS application structure...');
      await this.analyzeProjectStructure();

      console.log('🔍 Extracting entity definitions...');
      await this.extractEntityDefinitions();

      console.log('🤖 Generating AI-based STRIDE threat models...');
      await this.generateAIThreatModels();

      if (this.options.includeGlobalThreats) {
        console.log('🌐 Generating global application threat analysis...');
        await this.generateGlobalThreatAnalysis();
      }

      console.log('📝 Writing threat model to file...');
      await this.writeThreatModelToFile();

      console.log('✅ STRIDE threat model generation complete!');

      // Cleanup
      if (this.app) {
        await this.app.close();
      }
    } catch (error) {
      console.error('❌ Error generating threat model:', error);
      throw error;
    }
  }

  /**
   * Generate a global application security assessment
   */
  private async generateGlobalThreatAnalysis(): Promise<void> {
    try {
      // Create a consolidated view of application structure for the global analysis
      const applicationSummary = {
        controllers: this.appStructure.flatMap((m) => m.controllers.map((c) => c.name)),
        endpoints: this.appStructure.flatMap((m) =>
          m.controllers.flatMap((c) =>
            c.endpoints.map((e) => ({
              path: e.path,
              method: e.method,
              guards: e.guards,
            })),
          ),
        ),
        entities: Array.from(this.entityDefinitions.keys()),
        modules: this.appStructure.map((m) => m.name),
      };

      console.log(`🔄 Generating global application threat assessment`);

      // Create a prompt for Claude
      const prompt = `
        You are a cybersecurity expert specializing in NestJS application security. Given the following overview of a NestJS application,
        perform a comprehensive STRIDE threat model analysis focusing on architecture-level and application-wide security concerns.

        Application Structure:
        Controllers: ${applicationSummary.controllers.join(', ')}
        Total Endpoints: ${applicationSummary.endpoints.length}
        Entities: ${applicationSummary.entities.join(', ')}
        Modules: ${applicationSummary.modules.join(', ')}

        Please analyze potential security vulnerabilities from a global application perspective, including:
        1. Authentication and authorization mechanisms
        2. Data protection and privacy
        3. Infrastructure security
        4. Input validation and sanitization
        5. Logging and audit
        6. Error handling
        7. NestJS-specific security considerations

        For each STRIDE category, identify the top 2-3 global threats, their risk levels, and comprehensive mitigation strategies.
        Focus on NestJS and TypeScript security best practices.

        Format your response in a structured way with clear sections for each STRIDE category.
        For each threat include:
        1. A clear description of the threat
        2. The risk level (Low, Medium, High, or Critical)
        3. A detailed mitigation strategy
      `;

      // Call Claude API
      const completion = await this.claudeClient.messages.create({
        model: this.options.claudeModel as 'claude-3-7-sonnet-20250219',
        max_tokens: 4000,
        system: 'You are a cybersecurity expert specializing in threat modeling for NestJS applications.',
        messages: [{ role: 'user', content: prompt }],
        temperature: 0.7,
      });

      // Parse Claude's response
      const aiResponse = typeof completion.content[0] === 'object' && 'text' in completion.content[0] 
        ? completion.content[0].text as string 
        : '';

      // Parse the structured response into threat categories
      const threatCategories = [
        'Spoofing',
        'Tampering',
        'Repudiation',
        'Information Disclosure',
        'Denial of Service',
        'Elevation of Privilege',
      ];

      // Parse global threats from the AI response
      const globalThreats: ThreatModel = {
        assetName: 'Global Application',
        assetType: 'process',
        threats: [],
      };

      for (const category of threatCategories) {
        const regex = new RegExp(`${category}[\\s\\S]*?(?=(?:${threatCategories.join('|')})|$)`, 'i');
        const match = aiResponse.match(regex);
        const section = match ? match[0] : '';

        if (section.length > 20) {
          // Ensure we have meaningful content
          // Extract threats from this section
          const threatLines = section.split(/\n(?=\d+\.\s|\-\s|\*\s)/g);

          for (const line of threatLines) {
            if (line.trim().length < 20) continue; // Skip too short lines

            // Determine risk level
            let riskLevel: 'Low' | 'Medium' | 'High' | 'Critical' = 'Medium';
            if (line.toLowerCase().includes('high risk') || line.toLowerCase().includes('risk: high')) {
              riskLevel = 'High';
            } else if (line.toLowerCase().includes('critical risk') || line.toLowerCase().includes('risk: critical')) {
              riskLevel = 'Critical';
            } else if (line.toLowerCase().includes('low risk') || line.toLowerCase().includes('risk: low')) {
              riskLevel = 'Low';
            }

            // Extract description (simplified)
            let description = line.replace(/^\d+\.\s|\-\s|\*\s/, '').trim();
            if (description.includes('Mitigation')) {
              description = description.split(/Mitigation|Risk/i)[0].trim();
            }

            // Extract mitigation
            const mitigationMatch = line.match(/mitigation[:\s]+(.*?)(?=\n\n|\n$|$)/i);
            const mitigationStrategy = mitigationMatch
              ? mitigationMatch[1].trim()
              : 'Implement proper security controls';

            if (description.length > 10) {
              globalThreats.threats.push({
                category: category as any,
                description,
                riskLevel,
                mitigationStrategy,
              });
            }
          }
        }
      }

      // Add the global threat model to our collection
      if (globalThreats.threats.length > 0) {
        this.threatModels.push(globalThreats);
      }
    } catch (error) {
      console.warn(`⚠️ Error generating global threat analysis: ${error.message}`);
    }
  }

  private async analyzeProjectStructure(): Promise<void> {
    // Create a temporary NestJS app to access metadata
    const app = await NestFactory.create(this.appModule, { logger: false });
    const moduleRef = app.get(ModuleRef);
    const discoveryService = app.get(DiscoveryService);
    const metadataScanner = app.get(MetadataScanner);

    // Get all controllers
    const controllers = discoveryService.getControllers();

    // Loop through modules and build structure
    // This is a simplified version - in a real app you'd need to recursively scan modules
    this.appStructure = [
      {
        name: this.appModule.name,
        controllers: [],
        providers: [],
        imports: [],
        exports: [],
      },
    ];

    // Process controllers
    for (const controller of controllers) {
      const controllerInfo: ControllerInfo = {
        name: controller.name,
        endpoints: [],
      };

      // Get methods/endpoints
      const prototype = Object.getPrototypeOf(controller.instance);
      const methods = metadataScanner.getAllMethodNames(prototype);

      for (const method of methods) {
        if (method !== 'constructor') {
          const endpoint: ControllerEndpoint = {
            path: this.getPath(controller, method),
            method: this.getHttpMethod(controller, method),
            handler: method,
            guards: this.getGuards(controller, method),
          };
          controllerInfo.endpoints.push(endpoint);
        }
      }

      this.appStructure[0].controllers.push(controllerInfo);
    }

    await app.close();
  }

  private getPath(controller: any, method: string): string {
    // This is simplified - you'd need to extract real path from metadata
    return `/${controller.name.toLowerCase()}/${method}`;
  }

  private getHttpMethod(controller: any, method: string): string {
    // Simplified - would extract from metadata
    if (method.startsWith('get')) return 'GET';
    if (method.startsWith('post')) return 'POST';
    if (method.startsWith('put')) return 'PUT';
    if (method.startsWith('delete')) return 'DELETE';
    if (method.startsWith('patch')) return 'PATCH';
    return 'GET';
  }

  private getGuards(controller: any, method: string): string[] {
    // Simplified - would extract from metadata
    return ['JwtAuthGuard'];
  }

  private async extractEntityDefinitions(): Promise<void> {
    try {
      // Find all entity files recursively in the src directory
      const entityFiles = await this.findEntityFiles(path.join(this.projectRoot, 'src'));

      for (const entityPath of entityFiles) {
        try {
          const content = await fs.readFile(entityPath, 'utf8');
          // Extract the entity name from the file path
          const fileName = path.basename(entityPath);
          const entityName = fileName.replace('.entity.ts', '');

          // Extract class name from the content to get a more accurate entity name
          const classNameMatch = content.match(/export\s+class\s+(\w+)/);
          const className = classNameMatch ? classNameMatch[1] : entityName;

          this.entityDefinitions.set(className, content);
          console.log(`📋 Found entity: ${className}`);
        } catch (error) {
          console.warn(`⚠️ Error reading entity file ${entityPath}: ${error.message}`);
        }
      }

      console.log(`✅ Extracted ${this.entityDefinitions.size} entities`);
    } catch (error) {
      console.warn(`⚠️ Error extracting entity definitions: ${error.message}`);
    }
  }

  private async findEntityFiles(dir: string): Promise<string[]> {
    const entityFiles: string[] = [];

    try {
      const entries = await fs.readdir(dir, { withFileTypes: true });

      for (const entry of entries) {
        const fullPath = path.join(dir, entry.name);

        if (entry.isDirectory()) {
          // Skip node_modules and dist directories
          if (entry.name !== 'node_modules' && entry.name !== 'dist') {
            entityFiles.push(...(await this.findEntityFiles(fullPath)));
          }
        } else if (entry.name.endsWith('.entity.ts')) {
          entityFiles.push(fullPath);
        }
      }
    } catch (error) {
      console.warn(`⚠️ Error reading directory ${dir}: ${error.message}`);
    }

    return entityFiles;
  }

  private async generateAIThreatModels(): Promise<void> {
    // Process each controller endpoint
    for (const module of this.appStructure) {
      for (const controller of module.controllers) {
        for (const endpoint of controller.endpoints) {
          // Generate STRIDE threat model for each endpoint using AI
          const threatModel = await this.generateEndpointThreatModel(controller.name, endpoint);
          this.threatModels.push(threatModel);
        }
      }
    }

    // Generate data-related threat models
    for (const [entityName, entityDef] of this.entityDefinitions.entries()) {
      const threatModel = await this.generateDataThreatModel(entityName, entityDef);
      this.threatModels.push(threatModel);
    }
  }

  private async generateEndpointThreatModel(
    controllerName: string,
    endpoint: ControllerEndpoint,
  ): Promise<ThreatModel> {
    console.log(`🔄 Generating threat model for ${endpoint.method} ${endpoint.path}`);

    // Create a prompt for Claude
    const prompt = `
You are a cybersecurity expert specializing in threat modeling. Given the following NestJS API endpoint,
generate a STRIDE threat model (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege).

Controller: ${controllerName}
Endpoint: ${endpoint.path}
HTTP Method: ${endpoint.method}
Authorization: ${endpoint.guards.join(', ')}

For each STRIDE category, identify specific threats, assess their risk level, and suggest appropriate mitigation strategies.
Focus on NestJS-specific vulnerabilities and TypeScript best practices.

Format your response in a consistent structured way with clear sections for each STRIDE category.
For each category include:
1. A brief description of the threat
2. The risk level (Low, Medium, High, or Critical)
3. A mitigation strategy
`;

    // Call Claude API
    const completion = await this.claudeClient.messages.create({
      model: this.options.claudeModel as 'claude-3-7-sonnet-20250219',
      max_tokens: 4000,
      system: 'You are a cybersecurity expert specializing in threat modeling for NestJS applications.',
      messages: [{ role: 'user', content: prompt }],
      temperature: 0.7,
    });

    // Parse Claude's response
    const aiResponse = typeof completion.content[0] === 'object' && 'text' in completion.content[0] 
      ? completion.content[0].text as string 
      : '';

    // Parse the structured response into threat categories
    const threatCategories = [
      'Spoofing',
      'Tampering',
      'Repudiation',
      'Information Disclosure',
      'Denial of Service',
      'Elevation of Privilege',
    ];

    const threats = threatCategories.map((category) => {
      // Extract relevant section from AI response
      const regex = new RegExp(`${category}[\\s\\S]*?(?=(?:${threatCategories.join('|')})|$)`, 'i');
      const match = aiResponse.match(regex);
      const section = match ? match[0] : '';

      // Simplified risk level extraction
      let riskLevel: 'Low' | 'Medium' | 'High' | 'Critical' = 'Medium';
      if (section.toLowerCase().includes('high risk') || section.toLowerCase().includes('risk: high')) {
        riskLevel = 'High';
      } else if (section.toLowerCase().includes('critical risk') || section.toLowerCase().includes('risk: critical')) {
        riskLevel = 'Critical';
      } else if (section.toLowerCase().includes('low risk') || section.toLowerCase().includes('risk: low')) {
        riskLevel = 'Low';
      }

      // Extract mitigation strategy
      const mitigationMatch = section.match(/mitigation[:\s]+(.*?)(?=\n\n|\n$|$)/i);
      const mitigationStrategy = mitigationMatch ? mitigationMatch[1].trim() : 'Implement proper security controls';

      // Extract description
      let description = section.replace(category, '').trim();
      if (description.includes('Mitigation')) {
        description = description.split('Mitigation')[0].trim();
      }
      if (description.length > 150) {
        description = description.substring(0, 150) + '...';
      }

      return {
        category: category as any,
        description,
        riskLevel,
        mitigationStrategy,
      };
    });

    return {
      assetName: `${endpoint.method} ${endpoint.path}`,
      assetType: 'endpoint',
      threats: threats.filter((t) => t.description.length > 10), // Filter out empty threats
    };
  }

  private async generateDataThreatModel(entityName: string, entityDef: string): Promise<ThreatModel> {
    console.log(`🔄 Generating threat model for ${entityName} entity`);

    // Create a prompt for Claude
    const prompt = `
You are a cybersecurity expert specializing in threat modeling. Given the following TypeScript entity definition
from a NestJS application, generate a STRIDE threat model focusing on data security.

Entity Name: ${entityName}
Entity Definition:
\`\`\`typescript
${entityDef}
\`\`\`

For each STRIDE category, identify specific threats to this data entity, assess their risk level,
and suggest appropriate mitigation strategies. Focus on data protection, privacy, and secure storage practices.

Format your response in a consistent structured way with clear sections for each STRIDE category.
For each category include:
1. A brief description of the threat
2. The risk level (Low, Medium, High, or Critical)
3. A mitigation strategy
`;

    // Call Claude API
    const completion = await this.claudeClient.messages.create({
      model: this.options.claudeModel as 'claude-3-7-sonnet-20250219',
      max_tokens: 4000,
      system: 'You are a cybersecurity expert specializing in data security for NestJS applications.',
      messages: [{ role: 'user', content: prompt }],
      temperature: 0.7,
    });

    // Parse Claude's response
    const aiResponse = typeof completion.content[0] === 'object' && 'text' in completion.content[0] 
      ? completion.content[0].text as string 
      : '';

    // Parse the structured response into threat categories
    const threatCategories = [
      'Spoofing',
      'Tampering',
      'Repudiation',
      'Information Disclosure',
      'Denial of Service',
      'Elevation of Privilege',
    ];

    const threats = threatCategories.map((category) => {
      // Extract relevant section from AI response
      const regex = new RegExp(`${category}[\\s\\S]*?(?=(?:${threatCategories.join('|')})|$)`, 'i');
      const match = aiResponse.match(regex);
      const section = match ? match[0] : '';

      // Same processing as in the endpoint method
      let riskLevel: 'Low' | 'Medium' | 'High' | 'Critical' = 'Medium';
      if (section.toLowerCase().includes('high risk') || section.toLowerCase().includes('risk: high')) {
        riskLevel = 'High';
      } else if (section.toLowerCase().includes('critical risk') || section.toLowerCase().includes('risk: critical')) {
        riskLevel = 'Critical';
      } else if (section.toLowerCase().includes('low risk') || section.toLowerCase().includes('risk: low')) {
        riskLevel = 'Low';
      }

      const mitigationMatch = section.match(/mitigation[:\s]+(.*?)(?=\n\n|\n$|$)/i);
      const mitigationStrategy = mitigationMatch ? mitigationMatch[1].trim() : 'Implement proper security controls';

      let description = section.replace(category, '').trim();
      if (description.includes('Mitigation')) {
        description = description.split('Mitigation')[0].trim();
      }
      if (description.length > 150) {
        description = description.substring(0, 150) + '...';
      }

      return {
        category: category as any,
        description,
        riskLevel,
        mitigationStrategy,
      };
    });

    return {
      assetName: entityName,
      assetType: 'data',
      threats: threats.filter((t) => t.description.length > 10), // Filter out empty threats
    };
  }

  private async writeThreatModelToFile(): Promise<void> {
    const outputFile = path.join(this.projectRoot, 'threat-model.json');
    await fs.writeFile(outputFile, JSON.stringify(this.threatModels, null, 2), 'utf8');

    // Also generate a markdown report
    await this.generateMarkdownReport();
  }

  private async generateMarkdownReport(): Promise<void> {
    const outputPath = this.options.outputPath || this.projectRoot;
    const reportFile = path.join(outputPath, 'threat-model-report.md');

    let markdownContent = `# NestJS Application STRIDE Threat Model\n\n`;
    markdownContent += `*Generated on ${new Date().toLocaleString()}*\n\n`;

    // Calculate statistics
    const totalThreats = this.threatModels.reduce((acc, tm) => acc + tm.threats.length, 0);
    const criticalThreats = this.threatModels.flatMap((tm) =>
      tm.threats
        .filter((t) => t.riskLevel === 'Critical')
        .map((t) => ({ asset: tm.assetName, assetType: tm.assetType, ...t })),
    );
    const highThreats = this.threatModels.flatMap((tm) =>
      tm.threats
        .filter((t) => t.riskLevel === 'High')
        .map((t) => ({ asset: tm.assetName, assetType: tm.assetType, ...t })),
    );
    const mediumThreats = this.threatModels.flatMap((tm) =>
      tm.threats
        .filter((t) => t.riskLevel === 'Medium')
        .map((t) => ({ asset: tm.assetName, assetType: tm.assetType, ...t })),
    );
    const lowThreats = this.threatModels.flatMap((tm) =>
      tm.threats
        .filter((t) => t.riskLevel === 'Low')
        .map((t) => ({ asset: tm.assetName, assetType: tm.assetType, ...t })),
    );

    // Calculate percentages
    const criticalPercentage = ((criticalThreats.length / totalThreats) * 100).toFixed(1);
    const highPercentage = ((highThreats.length / totalThreats) * 100).toFixed(1);
    const mediumPercentage = ((mediumThreats.length / totalThreats) * 100).toFixed(1);
    const lowPercentage = ((lowThreats.length / totalThreats) * 100).toFixed(1);

    // Executive Summary
    markdownContent += `## Executive Summary\n\n`;
    markdownContent += `This report presents a comprehensive security analysis of the NestJS application using the STRIDE threat modeling methodology. `;
    markdownContent += `The analysis identified **${totalThreats} potential security threats** across endpoints, data entities, and application architecture.\n\n`;

    // Risk Distribution
    markdownContent += `### Risk Level Distribution\n`;
    markdownContent += `- **Critical**: ${criticalThreats.length} threats (${criticalPercentage}%)\n`;
    markdownContent += `- **High**: ${highThreats.length} threats (${highPercentage}%)\n`;
    markdownContent += `- **Medium**: ${mediumThreats.length} threats (${mediumPercentage}%)\n`;
    markdownContent += `- **Low**: ${lowThreats.length} threats (${lowPercentage}%)\n\n`;

    // Asset Analysis
    markdownContent += `### Asset Analysis\n`;
    markdownContent += `- **Total Assets Analyzed**: ${this.threatModels.length}\n`;
    markdownContent += `- **Endpoints**: ${this.threatModels.filter((tm) => tm.assetType === 'endpoint').length}\n`;
    markdownContent += `- **Data Entities**: ${this.threatModels.filter((tm) => tm.assetType === 'data').length}\n`;
    if (this.threatModels.filter((tm) => tm.assetType === 'process').length > 0) {
      markdownContent += `- **Process/Architecture**: ${
        this.threatModels.filter((tm) => tm.assetType === 'process').length
      }\n`;
    }
    markdownContent += `\n`;

    // Top Threat Categories Analysis
    const threatCategoryCount = new Map<string, number>();
    this.threatModels.forEach((tm) => {
      tm.threats.forEach((threat) => {
        const currentCount = threatCategoryCount.get(threat.category) || 0;
        threatCategoryCount.set(threat.category, currentCount + 1);
      });
    });

    const sortedCategories = Array.from(threatCategoryCount.entries())
      .sort((a, b) => b[1] - a[1])
      .slice(0, 3);

    if (sortedCategories.length > 0) {
      markdownContent += `### Top Vulnerability Categories\n`;
      sortedCategories.forEach((category, index) => {
        markdownContent += `${index + 1}. **${category[0]}** - ${category[1]} threats identified\n`;
      });
      markdownContent += `\n`;
    }

    // Critical Vulnerabilities Section
    if (criticalThreats.length > 0) {
      markdownContent += `## Critical Vulnerabilities\n\n`;

      criticalThreats.forEach((threat, index) => {
        markdownContent += `### ${index + 1}. ${threat.category} in ${threat.asset}\n`;
        markdownContent += `**Risk**: Critical  \n`;
        markdownContent += `**Description**: ${threat.description}  \n`;
        markdownContent += `**Mitigation**: ${threat.mitigationStrategy}  \n\n`;
      });
    }

    // High-Risk Vulnerabilities Section
    if (highThreats.length > 0) {
      markdownContent += `## High-Risk Vulnerabilities\n\n`;

      // Group high threats by category
      const categorizedHighThreats = highThreats.reduce(
        (acc, threat) => {
          const category = threat.category;
          if (!acc[category]) {
            acc[category] = [];
          }
          acc[category].push(threat);
          return acc;
        },
        {} as Record<string, typeof highThreats>,
      );

      // Output each category
      Object.entries(categorizedHighThreats).forEach(([category, threats]) => {
        markdownContent += `### ${category}\n`;

        threats.forEach((threat, index) => {
          markdownContent += `${index + 1}. **${threat.asset}** (${threat.assetType})  \n`;
          markdownContent += `   **Description**: ${threat.description}  \n`;
          markdownContent += `   **Mitigation**: ${threat.mitigationStrategy}  \n\n`;
        });
      });
    }

    // Endpoint Analysis Section
    const endpointModels = this.threatModels.filter((tm) => tm.assetType === 'endpoint');
    if (endpointModels.length > 0) {
      markdownContent += `## API Endpoint Security Analysis\n\n`;

      // Find the most vulnerable endpoints (those with most high/critical threats)
      const endpointVulnerabilityScores = endpointModels
        .map((model) => {
          const criticalCount = model.threats.filter((t) => t.riskLevel === 'Critical').length;
          const highCount = model.threats.filter((t) => t.riskLevel === 'High').length;
          const score = criticalCount * 3 + highCount;
          return { name: model.assetName, score, threatModel: model };
        })
        .sort((a, b) => b.score - a.score);

      // Detail the most vulnerable endpoints (top 3)
      const topVulnerableEndpoints = endpointVulnerabilityScores.slice(0, 3);

      if (topVulnerableEndpoints.length > 0 && topVulnerableEndpoints[0].score > 0) {
        markdownContent += `### Most Vulnerable Endpoints\n\n`;

        topVulnerableEndpoints.forEach((endpoint) => {
          if (endpoint.score > 0) {
            markdownContent += `#### ${endpoint.name}\n\n`;

            // List critical threats for this endpoint
            const criticalThreats = endpoint.threatModel.threats.filter((t) => t.riskLevel === 'Critical');
            if (criticalThreats.length > 0) {
              markdownContent += `**Critical Threats:**\n`;
              criticalThreats.forEach((threat) => {
                markdownContent += `- **${threat.category}**: ${threat.description}\n`;
                markdownContent += `  - Mitigation: ${threat.mitigationStrategy}\n`;
              });
              markdownContent += `\n`;
            }

            // List high threats for this endpoint
            const highThreats = endpoint.threatModel.threats.filter((t) => t.riskLevel === 'High');
            if (highThreats.length > 0) {
              markdownContent += `**High-Risk Threats:**\n`;
              highThreats.forEach((threat) => {
                markdownContent += `- **${threat.category}**: ${threat.description}\n`;
                markdownContent += `  - Mitigation: ${threat.mitigationStrategy}\n`;
              });
              markdownContent += `\n`;
            }
          }
        });
      }
    }

    // Entity Security Analysis
    const entityModels = this.threatModels.filter((tm) => tm.assetType === 'data');
    if (entityModels.length > 0) {
      markdownContent += `## Data Entity Security Analysis\n\n`;

      // Find entities with high/critical security issues
      const entitiesWithHighRisk = entityModels.filter((model) =>
        model.threats.some((t) => t.riskLevel === 'Critical' || t.riskLevel === 'High'),
      );

      if (entitiesWithHighRisk.length > 0) {
        entitiesWithHighRisk.forEach((entity) => {
          markdownContent += `### ${entity.assetName}\n\n`;

          // Group threats by risk level
          const criticalThreats = entity.threats.filter((t) => t.riskLevel === 'Critical');
          const highThreats = entity.threats.filter((t) => t.riskLevel === 'High');
          const mediumThreats = entity.threats.filter((t) => t.riskLevel === 'Medium');

          if (criticalThreats.length > 0) {
            markdownContent += `**Critical Risks:**\n`;
            criticalThreats.forEach((threat) => {
              markdownContent += `- **${threat.category}**: ${threat.description}\n`;
              markdownContent += `  - Mitigation: ${threat.mitigationStrategy}\n`;
            });
            markdownContent += `\n`;
          }

          if (highThreats.length > 0) {
            markdownContent += `**High Risks:**\n`;
            highThreats.forEach((threat) => {
              markdownContent += `- **${threat.category}**: ${threat.description}\n`;
              markdownContent += `  - Mitigation: ${threat.mitigationStrategy}\n`;
            });
            markdownContent += `\n`;
          }

          if (mediumThreats.length > 0) {
            markdownContent += `**Medium Risks:**\n`;
            markdownContent += `- Found ${mediumThreats.length} medium-risk issues including ${mediumThreats
              .map((t) => t.category)
              .join(', ')}\n\n`;
          }
        });
      } else {
        markdownContent += `No high or critical risk issues were found in the data entities.\n\n`;
      }
    }

    // Global Security Recommendations
    markdownContent += `## Global Security Recommendations\n\n`;

    // Group all threats by category
    const allThreatsByCategory = this.threatModels
      .flatMap((tm) => tm.threats.map((t) => ({ asset: tm.assetName, assetType: tm.assetType, ...t })))
      .reduce(
        (acc, threat) => {
          const category = threat.category;
          if (!acc[category]) {
            acc[category] = [];
          }
          acc[category].push(threat);
          return acc;
        },
        {} as Record<string, any[]>,
      );

    // Output security recommendations for each category
    Object.entries(allThreatsByCategory).forEach(([category, threats]) => {
      markdownContent += `### ${category} Mitigations\n\n`;

      // Get unique mitigation strategies (simplify repeated ones)
      const uniqueMitigations = new Set<string>();
      threats
        .filter((t) => t.riskLevel === 'Critical' || t.riskLevel === 'High')
        .forEach((threat) => {
          uniqueMitigations.add(threat.mitigationStrategy);
        });

      if (uniqueMitigations.size > 0) {
        Array.from(uniqueMitigations).forEach((mitigation) => {
          markdownContent += `- ${mitigation}\n`;
        });
      } else {
        markdownContent += `- No critical or high-risk ${category} threats identified\n`;
      }

      markdownContent += `\n`;
    });

    // Recommended Implementation Timeline
    markdownContent += `## Recommended Implementation Timeline\n\n`;

    if (criticalThreats.length > 0) {
      markdownContent += `### Immediate (within 1 week)\n`;
      markdownContent += criticalThreats
        .map((threat) => `- ${threat.mitigationStrategy} (${threat.asset}, ${threat.category})`)
        .join('\n');
      markdownContent += `\n\n`;
    }

    if (highThreats.length > 0) {
      markdownContent += `### Short-term (1-4 weeks)\n`;
      // Just include a subset of high threats to keep the list manageable
      markdownContent += highThreats
        .slice(0, Math.min(highThreats.length, 5))
        .map((threat) => `- ${threat.mitigationStrategy} (${threat.category})`)
        .join('\n');

      if (highThreats.length > 5) {
        markdownContent += `\n- Plus ${highThreats.length - 5} additional high-risk mitigations`;
      }
      markdownContent += `\n\n`;
    }

    markdownContent += `### Medium-term (1-3 months)\n`;
    markdownContent += `- Implement comprehensive audit logging\n`;
    markdownContent += `- Establish regular security testing\n`;
    markdownContent += `- Develop security regression test suite\n\n`;

    markdownContent += `### Long-term (3+ months)\n`;
    markdownContent += `- Conduct penetration testing\n`;
    markdownContent += `- Implement security monitoring\n`;
    markdownContent += `- Establish security incident response plan\n\n`;

    // Conclusion
    markdownContent += `## Conclusion\n\n`;
    markdownContent += `This STRIDE threat model analysis identified ${totalThreats} potential security threats, with ${criticalThreats.length} critical and ${highThreats.length} high-risk issues that should be addressed promptly. `;
    markdownContent += `By implementing the recommended mitigations, particularly those marked as Critical and High risk, the application's security posture will be significantly improved.\n\n`;

    markdownContent += `---\n\n`;
    markdownContent += `*Generated automatically using NestJS STRIDE Threat Modeling Tool*\n`;
    markdownContent += `*Based on Claude AI analysis*`;

    await fs.writeFile(reportFile, markdownContent, 'utf8');
    console.log(`✅ Threat model report written to ${reportFile}`);
  }
}

// Return type for the generateAIStrideModel function
interface ThreatModelResult {
  jsonPath: string;
  reportPath: string;
}

// Usage example
export async function generateAIStrideModel(
  appModule: any,
  options?: {
    outputPath?: string;
    includeGlobalThreats?: boolean;
    includeEntityThreats?: boolean;
    claudeModel?: string;
  }
): Promise<ThreatModelResult> {
  const projectRoot = process.cwd();
  const generator = new StrideModelGenerator(projectRoot, appModule, options);
  await generator.generateThreatModel();
  
  // Return paths to the generated files
  return {
    jsonPath: path.join(options?.outputPath || projectRoot, 'threat-model.json'),
    reportPath: path.join(options?.outputPath || projectRoot, 'threat-model-report.md')
  };
}
