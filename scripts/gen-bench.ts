import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const outDir = path.join(__dirname, '../bench-files');
if (!fs.existsSync(outDir)) {
  fs.mkdirSync(outDir);
}

for (let i = 0; i < 100; i++) {
  const content = `
import express from 'express';
const app = express();

app.get('/vuln${i}', (req, res) => {
    // SQLi
    const q = "SELECT * FROM users WHERE id = " + req.query.id;
    db.query(q);
    
    // XSS
    res.send("Hello " + req.query.name);
    
    // Command Injection
    require('child_process').exec("ls " + req.query.dir);
});

// Large AST filler
function doNothing${i}() {
    let x = 0;
    for(let j=0; j<1000; j++) {
        x += j;
        if(x > 500) {
            x -= 10;
        }
    }
    return x;
}
  `;
  fs.writeFileSync(path.join(outDir, `file${i}.ts`), content);
}

console.log('Created 100 vulnerable files in bench-files/');