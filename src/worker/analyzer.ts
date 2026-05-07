import { parentPort } from 'node:worker_threads';
import { Analyzer } from '../core/analyzer';
import { Parser } from '../core/parser';
import { loadCustomRules } from '../rules/loader';
import { RuleRegistry } from '../rules/registry';
import { ALL_RULES } from '../rules/index';
import type { basesecConfig, Finding } from '../rules/types';

export interface WorkerInput {
  file: { filePath: string; content: string };
  config: basesecConfig;
  frameworks: string[];
  ruleIds: string[];
}

export interface WorkerOutput {
  filePath: string;
  findings: Finding[];
}

async function runAnalysis() {
  if (!parentPort) return;

  parentPort.on('message', async (message: WorkerInput) => {
    try {
      const { file, config, frameworks, ruleIds } = message;
      
      const registry = new RuleRegistry();
      registry.registerMany(ALL_RULES);
      
      if (config.rules && config.rules.length > 0) {
        await loadCustomRules(config.rules, registry);
      }
      
      const allAvailableRules = registry.getAll();
      const rulesToRun = allAvailableRules.filter(r => ruleIds.includes(r.id));
      
      // Parse file in worker thread
      const parser = new Parser();
      const parsedFile = parser.parseContent(file.filePath, file.content);
      
      if ('error' in parsedFile) {
        throw new Error(parsedFile.error);
      }
      
      const analyzer = new Analyzer();
      const findings = analyzer.analyze([parsedFile], rulesToRun, config, frameworks);
      
      parentPort?.postMessage({
        type: 'success',
        filePath: file.filePath,
        findings
      });
    } catch (error) {
      parentPort?.postMessage({
        type: 'error',
        filePath: message.file?.filePath || 'unknown',
        error: error instanceof Error ? error.message : String(error)
      });
    }
  });
}

runAnalysis();