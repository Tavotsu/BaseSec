import { writeFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));

const GITHUB_TOKEN = process.env.GITHUB_TOKEN;
const OWNER = 'Tavotsu';
const REPO = 'BaseSec';
const NPM_PACKAGE = 'basesec';

async function fetchGitHub(path) {
  const res = await fetch(`https://api.github.com/repos/${OWNER}/${REPO}${path}`, {
    headers: {
      Authorization: `Bearer ${GITHUB_TOKEN}`,
      Accept: 'application/vnd.github+json',
      'X-GitHub-Api-Version': '2022-11-28',
    },
  });
  if (!res.ok) {
    console.warn(`GitHub API warning: ${res.status} for ${path}`);
    return null;
  }
  return res.json();
}

async function fetchNpm(period) {
  const res = await fetch(
    `https://api.npmjs.org/downloads/point/${period}/${NPM_PACKAGE}`
  );
  if (!res.ok) return { downloads: 0 };
  return res.json();
}

async function main() {
  console.log('Fetching stats...');

  const [repoData, views, clones, weeklyNpm, monthlyNpm] = await Promise.all([
    fetchGitHub(''),
    fetchGitHub('/traffic/views'),
    fetchGitHub('/traffic/clones'),
    fetchNpm('last-week'),
    fetchNpm('last-month'),
  ]);

  const stats = {
    updatedAt: new Date().toISOString(),
    github: {
      stars: repoData?.stargazers_count ?? 0,
      forks: repoData?.forks_count ?? 0,
      openIssues: repoData?.open_issues_count ?? 0,
      views: {
        count: views?.count ?? 0,
        uniques: views?.uniques ?? 0,
      },
      clones: {
        count: clones?.count ?? 0,
        uniques: clones?.uniques ?? 0,
      },
    },
    npm: {
      weeklyDownloads: weeklyNpm?.downloads ?? 0,
      monthlyDownloads: monthlyNpm?.downloads ?? 0,
    },
  };

  const outputPath = join(__dirname, '..', 'public', 'stats.json');
  writeFileSync(outputPath, JSON.stringify(stats, null, 2));

  console.log('Stats written successfully:');
  console.log(JSON.stringify(stats, null, 2));
}

main().catch((err) => {
  console.error('Failed to fetch stats:', err);
  process.exit(1);
});
