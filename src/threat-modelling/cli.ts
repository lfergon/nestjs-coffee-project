#!/usr/bin/env node
import { AppModule } from '../app.module';
import { ThreatModellingModule } from './threat-modelling.module';

// Create and execute the command
const program = ThreatModellingModule.createCommand(AppModule);
program.parse(process.argv);