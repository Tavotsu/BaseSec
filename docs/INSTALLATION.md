# Installation

## Requirements

- Node.js 18+
- pnpm, npm, or yarn

## Global Installation (Recommended for CLI use)

### npm

```bash
npm install -g basesec
basesec scan ./src
```

### pnpm

```bash
pnpm add -g basesec
basesec scan ./src
```

### yarn

```bash
yarn global add basesec
basesec scan ./src
```

## Local Installation (Recommended for CI/CD)

```bash
npm install --save-dev basesec
npx basesec scan ./src
```

## Development Installation

Clone the repository and install dependencies:

```bash
git clone https://github.com/tavotsu/basesec.git
cd basesec
pnpm install
pnpm build
node dist/index.js scan ./src
```

## Verify Installation

```bash
basesec --version
# outputs: basesec/0.1.0

basesec scan --help
```

## Uninstall

```bash
npm uninstall -g basesec
# or
pnpm remove -g basesec
```