const assert = require('node:assert/strict');
const { execFileSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { test } = require('node:test');
const { pathToFileURL } = require('node:url');

test('fresh pinning commits preserve unrelated work', t => {
	const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'pin test-'));
	t.after(() => fs.rmSync(directory, { recursive: true }));
	const env = Object.fromEntries(Object.entries(process.env)
		.filter(([key]) => !/^GIT_/i.test(key)));
	env.GIT_CONFIG_NOSYSTEM = '1';
	env.GIT_CONFIG_GLOBAL = os.devNull;
	const git = (...args) => execFileSync('git', args, {
		cwd: directory, env, encoding: 'utf8',
		stdio: ['ignore', 'pipe', 'pipe']
	}).trim();
	git('init', '-q', '--initial-branch=test', '--object-format=sha1');
	git('config', 'user.name', 'Pin Test');
	git('config', 'user.email', 'pins@example.com');
	const workflows = path.join(directory, '.github/workflows');
	fs.mkdirSync(workflows, { recursive: true });
	const file = path.join(workflows, 'main.yml');
	const write = text => fs.writeFileSync(file, text);
	const read = () => fs.readFileSync(file, 'utf8');
	const run = () => execFileSync(process.execPath,
		[path.join(__dirname, 'pin-github-actions-shas.js')],
		{ cwd: directory, env, stdio: ['ignore', 'pipe', 'pipe'] });
	const workflow = `on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: 'example/action@v1'
      - uses: example/action/subpath@v2
        if: false
      - uses: ./local-action
  reusable:
    uses: example/action/.github/workflows/test.yaml@master
`.replace(/\n/g, '\r\n');
	write(workflow);
	const another = path.join(workflows, 'another.yaml');
	fs.writeFileSync(another, workflow.replace('@v1', '@v2'));
	const unrelated = path.join(directory, 'unrelated');
	fs.writeFileSync(unrelated, 'original\n');
	git('add', '--', '.github/workflows', 'unrelated');
	git('commit', '-qm', 'Upstream workflows');
	const first = git('rev-parse', 'HEAD');
	git('tag', 'v1');
	git('tag', '-am', 'Annotated version', 'v2');
	git('commit', '--allow-empty', '-qm', 'Update action');
	const second = git('rev-parse', 'HEAD');
	const pinned = v1 => workflow
		.replace(/@v1'/, `@${v1}' # v1`)
		.replace('@v2', `@${first} # v2`)
		.replace('@master', `@${second} # master`);
	git('branch', 'master');
	git('branch', 'v1');
	git('config', `url.${pathToFileURL(directory).href}.insteadOf`,
		'https://github.com/example/action');
	fs.writeFileSync(unrelated, 'staged change\n');
	git('add', '--', 'unrelated');
	const expectedSubject =
		'ci: pin GitHub Actions to satisfy downstream policy';
	run();
	assert.equal(git('log', '-1', '--format=%s'), expectedSubject);
	assert.equal(git('rev-parse', 'HEAD^'), second);
	assert.equal(read(), pinned(first));
	assert.match(git('log', '-1', '--format=%B'),
		/Signed-off-by: Pin Test <pins@example.com>/);
	write(read().replace(/# v[12]/g, '# v0.0.0'));
	git('commit', '-qm', 'Release labels', '--', '.github/workflows');
	git('tag', '-f', 'v1', second);
	const beforeRefresh = git('rev-parse', 'HEAD');
	run();
	assert.equal(git('log', '-1', '--format=%s'), expectedSubject);
	assert.equal(git('rev-parse', 'HEAD^'), beforeRefresh);
	assert.equal(read(), pinned(second));
	assert.equal(fs.readFileSync(another, 'utf8'),
		pinned(first).replace('# v1', '# v2'));
	const head = git('rev-parse', 'HEAD');
	run();
	assert.equal(git('rev-parse', 'HEAD'), head);
	assert.equal(git('diff', '--cached', '--name-only'), 'unrelated');
	assert.equal(git('show', 'HEAD:unrelated'), 'original');
});
