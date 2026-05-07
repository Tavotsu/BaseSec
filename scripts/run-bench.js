import { execSync } from 'child_process';
import { performance } from 'perf_hooks';

function runBench(name, cmd) {
    console.log(`\n=== ${name} ===`);
    const start = performance.now();
    try {
        const out = execSync(cmd, { encoding: 'utf8' });
        const lines = out.split('\n');
        let dur = 'N/A';
        for(const line of lines) {
            if(line.includes('"duration"')) {
                dur = line.trim();
            }
        }
        console.log(`Time: ${(performance.now() - start).toFixed(2)}ms, CLI reported ${dur}`);
    } catch(e) {
        console.log('Error running bench');
    }
}

runBench('No Cache, No Workers', 'node dist/index.js scan src --no-cache --workers 0 --format json');
runBench('Cache, No Workers', 'node dist/index.js scan src --workers 0 --format json');
runBench('No Cache, Workers', 'node dist/index.js scan src --no-cache --workers 4 --format json');
runBench('Cache, Workers', 'node dist/index.js scan src --workers 4 --format json');
