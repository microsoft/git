const assert = require('node:assert/strict');
const { execFileSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { test } = require('node:test');
const { pathToFileURL } = require('node:url');

function setupRepository(t) {
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
	return { directory, git, workflows, file, write, read, run };
}

test('fresh pinning commits preserve unrelated work', t => {
	const { directory, git, workflows, write, read, run } =
		setupRepository(t);
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

function setupConflictedMerge(t, { refresh = false, conflict = false,
	changedPins = false, style = 'merge', markerSize = 7 } = {}) {
	const repository = setupRepository(t);
	const { directory, git, workflows, write, read, run } = repository;
	const workflow = `on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: example/action@v1
`.replace(/\n/g, '\r\n');
	write(workflow);
	const deleted = path.join(workflows, 'deleted.yml');
	fs.writeFileSync(deleted, workflow);
	const unrelated = path.join(directory, 'unrelated');
	fs.writeFileSync(unrelated, 'original\n');
	git('add', '--', '.github/workflows', 'unrelated');
	git('commit', '-qm', 'Upstream workflows');
	git('tag', 'v1');
	git('branch', 'upstream');
	git('config', `url.${pathToFileURL(directory).href}.insteadOf`,
		'https://github.com/example/action');
	run();
	if (refresh) {
		git('tag', '-f', 'v1', 'HEAD');
		run();
	}
	if (changedPins) {
		write(read().replace('# v1', '# v1; downstream note'));
		git('commit', '-qam', 'Annotate downstream action');
	}
	fs.writeFileSync(path.join(directory, 'downstream'), 'keep me\n');
	if (conflict)
		fs.writeFileSync(unrelated, 'downstream\n');
	git('add', '--', 'downstream', 'unrelated');
	git('commit', '-qm', 'Downstream changes');
	const head = git('rev-parse', 'HEAD');
	git('switch', '-q', 'upstream');
	write(workflow.replace('@v1', '@v2'));
	fs.writeFileSync(path.join(workflows, 'new workflow.yaml'),
		workflow.replace('@v1', '@v2'));
	fs.unlinkSync(deleted);
	fs.writeFileSync(unrelated, 'upstream\n');
	git('add', '--', '.github/workflows', 'unrelated');
	git('commit', '-qm', 'Update upstream workflows');
	git('tag', 'v2');
	const upstream = git('rev-parse', 'HEAD');
	git('switch', '-q', 'test');
	git('config', 'merge.conflictStyle', style);
	fs.writeFileSync(path.join(directory, '.git/info/attributes'),
		`.github/workflows/* conflict-marker-size=${markerSize}\n`);
	assert.throws(() => git('merge', '--no-edit', 'upstream'),
		error => error.status === 1);
	const snapshot = () => ({
		head: git('rev-parse', 'HEAD'),
		mergeHead: git('rev-parse', 'MERGE_HEAD'),
		index: git('ls-files', '--stage', '-z'),
		workflow: read(),
		unrelated: fs.readFileSync(unrelated, 'utf8')
	});
	return { ...repository, workflow, head, upstream, unrelated, snapshot };
}

test('revert, remerge, and repin resolve the whole merge tree', t => {
	const { directory, git, workflows, read, run, workflow, head,
		upstream } = setupConflictedMerge(t, { refresh: true });
	const untracked = path.join(directory, 'untracked');
	fs.writeFileSync(untracked, 'leave me alone\n');
	run();
	const expected = workflow.replace('@v1', `@${upstream} # v2`);
	assert.equal(read(), expected);
	assert.equal(fs.readFileSync(
		path.join(workflows, 'new workflow.yaml'), 'utf8'), expected);
	assert.equal(fs.existsSync(path.join(workflows, 'deleted.yml')), false);
	assert.equal(fs.readFileSync(
		path.join(directory, 'downstream'), 'utf8'), 'keep me\n');
	assert.equal(fs.readFileSync(path.join(directory, 'unrelated'), 'utf8'),
		'upstream\n');
	assert.equal(fs.readFileSync(untracked, 'utf8'), 'leave me alone\n');
	assert.equal(git('ls-files', '--unmerged'), '');
	assert.equal(git('diff', '--name-only'), '');
	assert.equal(git('rev-parse', 'HEAD'), head);
	assert.equal(git('rev-parse', 'MERGE_HEAD'), upstream);
	assert.equal(git('diff', '--cached', '--name-only'),
		'.github/workflows/deleted.yml\n' +
		'.github/workflows/main.yml\n' +
		'.github/workflows/new workflow.yaml\nunrelated');
});

test('merge validation accepts configured conflict markers', async t => {
	for (const [style, markerSize] of [['diff3', 7], ['zdiff3', 3]]) {
		await t.test(style, t => {
			const { git, read, run, workflow, upstream } =
				setupConflictedMerge(t, { style, markerSize });
			run();
			assert.equal(read(),
				workflow.replace('@v1', `@${upstream} # v2`));
			assert.equal(git('ls-files', '--unmerged'), '');
		});
	}
});

test('edited merge state is never overwritten', async t => {
	const changes = {
		'edited conflict': ({ file }) =>
			fs.appendFileSync(file, '# manual edit\n'),
		'staged resolution': ({ git }) =>
			git('add', '--', '.github/workflows/main.yml'),
		'unstaged unrelated edit': ({ unrelated }) =>
			fs.writeFileSync(unrelated, 'manual edit\n'),
		'staged unrelated edit': ({ git, unrelated }) => {
			fs.writeFileSync(unrelated, 'manual edit\n');
			git('add', '--', 'unrelated');
		}
	};
	for (const [name, change] of Object.entries(changes)) {
		await t.test(name, t => {
			const repository = setupConflictedMerge(t);
			change(repository);
			const before = repository.snapshot();
			assert.throws(repository.run,
				/Current merge does not match/);
			assert.deepEqual(repository.snapshot(), before);
		});
	}
});

test('conflicts remaining after unpinning are not resolved', t => {
	const { run, snapshot } = setupConflictedMerge(t, { conflict: true });
	const before = snapshot();
	assert.throws(run, /Merge still has conflicts without Action pins/);
	assert.deepEqual(snapshot(), before);
});

test('conflicting pin reverts leave the merge untouched', t => {
	const { run, snapshot } =
		setupConflictedMerge(t, { changedPins: true });
	const before = snapshot();
	assert.throws(run, /Cannot cleanly revert Action pinning commit/);
	assert.deepEqual(snapshot(), before);
});

test('failed Action resolution leaves the merge untouched', t => {
	const { git, run, snapshot } = setupConflictedMerge(t);
	git('tag', '-d', 'v2');
	const before = snapshot();
	assert.throws(run, /Cannot resolve Action ref: example\/action@v2/);
	assert.deepEqual(snapshot(), before);
});

test('a locked index leaves the merge untouched', t => {
	const { directory, run, snapshot } = setupConflictedMerge(t);
	const before = snapshot();
	const lock = path.join(directory, '.git/index.lock');
	fs.writeFileSync(lock, 'another Git operation\n');
	assert.throws(run, /index\.lock/);
	assert.deepEqual(snapshot(), before);
	assert.equal(fs.readFileSync(lock, 'utf8'), 'another Git operation\n');
});
