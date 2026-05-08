import * as os from 'node:os';
import { Worker } from 'node:worker_threads';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import type { Finding, basesecConfig, ParsedFile } from '../rules/types';
import type { WorkerInput, WorkerOutput } from '../worker/analyzer';

export interface WorkerTask {
  filePath: string;
  content: string;
  ruleIds: string[];
  config: basesecConfig;
  frameworks: string[];
  taintGraphJson?: string;
}

export interface WorkerResult {
  filePath: string;
  findings: Finding[];
  duration: number;
}

export interface WorkerError {
  filePath: string;
  error: string;
}

export function shouldUseWorkers(numFiles: number, cliWorkers?: number): boolean {
  if (cliWorkers !== undefined) {
    return cliWorkers > 0;
  }
  // Workers break under tsx (module resolution fails in worker threads)
  try {
    const __filename = fileURLToPath(import.meta.url);
    if (__filename.endsWith('.ts')) return false;
  } catch {}
  return numFiles > 50;
}

export function getWorkerCount(cliWorkers?: number): number {
  if (cliWorkers !== undefined && cliWorkers > 0) {
    return Math.min(cliWorkers, os.cpus().length);
  }
  return Math.min(Math.max(1, os.cpus().length - 1), 4);
}

export class WorkerPool {
  private workers: Worker[] = [];
  private taskQueue: { 
    input: WorkerInput; 
    resolve: (result: WorkerResult) => void; 
    reject: (err: Error) => void;
    startTime: number;
  }[] = [];
  private activeTasks: Map<Worker, { 
    filePath: string; 
    resolve: (result: WorkerResult) => void; 
    reject: (err: Error) => void;
    startTime: number;
  }> = new Map();

  constructor(private poolSize: number) {
    const __filename = fileURLToPath(import.meta.url);
    const __dirname = dirname(__filename);
    const isTs = __filename.endsWith('.ts');
    const workerPath = isTs 
      ? join(__dirname, '../worker/analyzer.ts') 
      : join(__dirname, 'worker.js');

    for (let i = 0; i < poolSize; i++) {
      const worker = new Worker(workerPath, isTs ? { execArgv: ['--import', 'tsx'] } : undefined);
      
      worker.on('message', (msg) => {
        const task = this.activeTasks.get(worker);
        if (!task) return;
        
        this.activeTasks.delete(worker);
        
        if (msg.type === 'success') {
          task.resolve({
            filePath: msg.filePath,
            findings: msg.findings,
            duration: Date.now() - task.startTime
          });
        } else {
          task.reject(new Error(msg.error));
        }
        
        this.pumpQueue();
      });

      worker.on('error', (err) => {
        const task = this.activeTasks.get(worker);
        if (task) {
          this.activeTasks.delete(worker);
          task.reject(err instanceof Error ? err : new Error(String(err)));
        }
        // Restart worker on crash
        const newWorker = new Worker(workerPath, isTs ? { execArgv: ['--import', 'tsx'] } : undefined);
        this.workers[this.workers.indexOf(worker)] = newWorker;
        this.setupWorkerEvents(newWorker);
        this.pumpQueue();
      });

      this.workers.push(worker);
    }
  }

  private setupWorkerEvents(worker: Worker) {
    // Same as constructor setup
    worker.on('message', (msg) => {
      const task = this.activeTasks.get(worker);
      if (!task) return;
      this.activeTasks.delete(worker);
      if (msg.type === 'success') {
        task.resolve({ filePath: msg.filePath, findings: msg.findings, duration: Date.now() - task.startTime });
      } else {
        task.reject(new Error(msg.error));
      }
      this.pumpQueue();
    });
  }

  async analyzeFile(input: WorkerInput): Promise<WorkerResult> {
    return new Promise((resolve, reject) => {
      this.taskQueue.push({ input, resolve, reject, startTime: Date.now() });
      this.pumpQueue();
    });
  }

  private pumpQueue() {
    if (this.taskQueue.length === 0) return;
    
    for (const worker of this.workers) {
      if (!this.activeTasks.has(worker)) {
        const task = this.taskQueue.shift();
        if (!task) return;
        
        this.activeTasks.set(worker, {
          filePath: task.input.file.filePath,
          resolve: task.resolve,
          reject: task.reject,
          startTime: task.startTime
        });
        
        worker.postMessage(task.input);
        return; // Break out, check queue later
      }
    }
  }

  async close() {
    await Promise.all(this.workers.map(w => w.terminate()));
  }
}