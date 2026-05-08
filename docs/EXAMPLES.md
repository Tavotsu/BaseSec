# Examples

## SQL Injection

### Vulnerable

```ts
app.get('/user', (req, res) => {
  const query = "SELECT * FROM users WHERE id = " + req.query.id;
  db.query(query);
});
```

### Secure

```ts
app.get('/user', (req, res) => {
  db.query('SELECT * FROM users WHERE id = ?', [req.query.id]);
});
```

## XSS via res.send()

### Vulnerable

```ts
app.get('/greet', (req, res) => {
  res.send('Hello ' + req.query.name);
});
```

### Secure

```ts
import { escapeHtml } from './utils';

app.get('/greet', (req, res) => {
  res.send('Hello ' + escapeHtml(req.query.name));
});
```

## Command Injection

### Vulnerable

```ts
import { exec } from 'child_process';

app.post('/backup', (req, res) => {
  exec('tar -czf backup.tar.gz ' + req.body.directory);
});
```

### Secure

```ts
import { execFile } from 'child_process';

app.post('/backup', (req, res) => {
  execFile('tar', ['-czf', 'backup.tar.gz', req.body.directory]);
});
```

## Path Traversal

### Vulnerable

```ts
import { readFile } from 'fs/promises';

app.get('/file', async (req, res) => {
  const content = await readFile(req.query.path);
  res.send(content);
});
```

### Secure

```ts
import { readFile } from 'fs/promises';
import path from 'path';

const UPLOAD_DIR = '/var/app/uploads';

app.get('/file', async (req, res) => {
  const safePath = path.join(UPLOAD_DIR, path.basename(req.query.path));
  if (!safePath.startsWith(UPLOAD_DIR)) {
    return res.status(400).send('Invalid path');
  }
  const content = await readFile(safePath);
  res.send(content);
});
```

## Hardcoded Secrets

### Vulnerable

```ts
const JWT_SECRET = 'my-super-secret-key-12345';
```

### Secure

```ts
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
  throw new Error('JWT_SECRET not set');
}
```

## Missing Helmet Middleware

### Vulnerable

```ts
import express from 'express';
const app = express();

app.use(express.json());
// No helmet
```

### Secure

```ts
import express from 'express';
import helmet from 'helmet';

const app = express();
app.use(helmet());
app.use(express.json());
```

## Insecure Cookies

### Vulnerable

```ts
res.cookie('session', token);
```

### Secure

```ts
res.cookie('session', token, {
  httpOnly: true,
  secure: true,
  sameSite: 'strict',
  maxAge: 3600000,
});
```

## Open Redirect

### Vulnerable

```ts
app.get('/redirect', (req, res) => {
  res.redirect(req.query.url);
});
```

### Secure

```ts
const ALLOWED_REDIRECTS = ['https://example.com/callback'];

app.get('/redirect', (req, res) => {
  const url = req.query.url;
  if (!ALLOWED_REDIRECTS.includes(url)) {
    return res.status(400).send('Invalid redirect');
  }
  res.redirect(url);
});
```

## Missing Error Handler

### Vulnerable

```ts
app.get('/data', async (req, res) => {
  const data = await fetchData();
  res.json(data); // If fetchData throws, Express returns stack trace
});
```

### Secure

```ts
app.get('/data', async (req, res, next) => {
  try {
    const data = await fetchData();
    res.json(data);
  } catch (err) {
    next(err);
  }
});

app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: 'Internal server error' });
});
```

## NoSQL Injection

### Vulnerable

```ts
app.get('/users', (req, res) => {
  User.find({ $where: req.query.filter });
});
```

### Secure

```ts
app.get('/users', (req, res) => {
  User.find({ name: req.query.name });
});
```