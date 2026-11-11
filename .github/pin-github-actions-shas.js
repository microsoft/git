#!/usr/bin/env node

const { execFileSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const pinningMessage = `ci: pin GitHub Actions to satisfy downstream policy

Microsoft Git inherits workflows that upstream maintains using symbolic
Action refs. Downstream organizational policy requires full commit IDs
instead, adding pin maintenance to this project's maintainers' workload.

Keep pins aligned with the original upstream Action refs in a fresh
downstream snapshot, independent of any earlier pinning commit.
`;

function gitOutput(args, options = {}) {
	return execFileSync('git', ['--no-pager', ...args], {
		encoding: 'utf8',
		stdio: ['pipe', 'pipe', 'pipe'],
		maxBuffer: 16 * 1024 * 1024,
		...options
	});
}

function git(...args) {
	return gitOutput(args).trim();
}

function withTemporaryIndex(callback) {
	const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'pin-index-'));
	const index = path.join(directory, 'index');
	const env = { ...process.env, GIT_INDEX_FILE: index };
	try {
		return callback((args, options = {}) =>
			gitOutput(args, { ...options, env }), index);
	} finally {
		fs.rmSync(directory, { recursive: true });
	}
}

function mergeTree(...args) {
	let output, clean = true;
	try {
		output = gitOutput(['merge-tree', '--write-tree',
			'--no-messages', '-z', ...args]);
	} catch (error) {
		if (error.status !== 1)
			throw error;
		output = error.stdout;
		clean = false;
	}
	const [tree, ...conflicts] = output.split('\0');
	return { tree, conflicts: conflicts.filter(Boolean), clean };
}

const isSHA = value => /^[0-9a-f]{40}$/i.test(value);
const uses = /^( *-? *uses: *)(["']?)([\w./-]+)@([^ \t"'\r\n]+)\2([^\r\n]*)/gm;
const useLine = new RegExp(uses.source);

function findOriginalActionRef(file, actionName, workflowHistory) {
	for (const patch of workflowHistory.split('\0')) {
		const removed = patch.replace(/^-/gm, '');
		const versions = [...removed.matchAll(uses)]
			.filter(use => use[3] === actionName &&
				!isSHA(use[4]))
			.map(use => use[4]);
		if (!versions.length)
			continue;
		const [version] = versions;
		if (versions.some(candidate => candidate !== version))
			throw new Error('Ambiguous Action ref: ' +
				`${file}, ${actionName}`);
		return version;
	}
	throw new Error(`Cannot recover Action ref: ${file}, ${actionName}`);
}

function readWorkflow(file, tree) {
	const text = tree ? gitOutput(['show', `${tree}:${file}`]) :
		fs.readFileSync(file, 'utf8');
	const parts = text.split(/(^ *-? *uses:[^\r\n]*)/m);
	const matches = parts.map(part => part.match(useLine))
		.filter(use => use && !use[3].startsWith('./'));
	const workflowHistory = matches.some(use => isSHA(use[4]))
		? git('log', '--follow', '-p', '-U0',
			'-Guses:.*@', '--no-ext-diff', '--no-textconv',
			'--format=%x00',
			...(tree ? ['HEAD', 'MERGE_HEAD'] : []), '--', file)
		: '';
	const actionRefs = matches.map(use => {
		const actionName = use[3];
		const version = isSHA(use[4]) ?
			findOriginalActionRef(
				file, actionName, workflowHistory) :
			use[4];
		const actionRepo = actionName.split('/').slice(0, 2).join('/');
		return {
			use, actionName, version,
			pinKey: `${actionRepo}@${version}`
		};
	});
	return { file, text, parts, actionRefs };
}

function resolveActionSHA(actionName, version) {
	const actionRepo = actionName.split('/').slice(0, 2).join('/');
	const actionTagRef = `refs/tags/${version}`;
	const output = git('ls-remote', '--quiet',
		`https://github.com/${actionRepo}`,
		actionTagRef, `${actionTagRef}^{}`, `refs/heads/${version}`);
	const actionRepoRefs = Object.fromEntries(output.split('\n')
		.map(line => line.split('\t').reverse()));
	const sha = actionRepoRefs[`${actionTagRef}^{}`] ||
		actionRepoRefs[actionTagRef] ||
		actionRepoRefs[`refs/heads/${version}`];
	if (!sha || !isSHA(sha))
		throw new Error('Cannot resolve Action ref: ' +
			`${actionName}@${version}`);
	return sha;
}

function substitute({ file, text, parts, actionRefs }, pins) {
	const replacements = new Map(actionRefs.map(actionRef => {
		const { use, version, pinKey } = actionRef;
		const [, prefix, quote, actionName, , suffix] = use;
		const sha = pins[pinKey];
		let note = suffix.trim().replace(/^#\s*/, '');
		if (note.startsWith(`${version}; `))
			note = note.slice(version.length + 2);
		else if (note === version || /^v?\d[\w.+-]*$/.test(note))
			note = '';
		const pinned = `${prefix}${quote}${actionName}@${sha}${quote}` +
			` # ${version}` + (note ? `; ${note}` : '');
		return [use[0], pinned];
	}));
	const updated = parts.map(part => replacements.get(part) ?? part)
		.join('');
	return updated === text ? null : [file, updated];
}

function pinWorkflows(tree) {
	const files = (tree ? git('ls-tree', '-r', '--name-only', '-z',
		tree, '--', '.github/workflows') :
		git('ls-files', '-z', '--', '.github/workflows'))
		.split('\0').filter(file => /\.ya?ml$/.test(file));
	const workflows = files.map(file => readWorkflow(file, tree));
	const actionRefs = workflows.flatMap(workflow => workflow.actionRefs);
	const uniquePins = new Map(actionRefs.map(actionRef =>
		[actionRef.pinKey, actionRef]));
	const pins = Object.fromEntries([...uniquePins.values()].map(
		({ pinKey, actionName, version }) =>
			[pinKey, resolveActionSHA(actionName, version)]));
	return workflows.map(workflow => substitute(workflow, pins))
		.filter(Boolean);
}

function validateMerge(merge, autoMerge) {
	const mismatch = () => {
		throw new Error('Current merge does not match ' +
			'git merge-tree HEAD MERGE_HEAD');
	};
	if (merge.clean)
		mismatch();
	const entryPath = entry => entry.slice(entry.indexOf('\t') + 1);
	const paths = new Set(merge.conflicts.map(entryPath));
	const expected = gitOutput(['ls-tree', '-r', '-z', merge.tree])
		.split('\0').filter(Boolean)
		.filter(entry => !paths.has(entryPath(entry)))
		.map(entry => entry.replace(/^(\d+) \w+ (\w+)\t/,
			'$1 $2 0\t'))
		.concat(merge.conflicts).sort().join('\0');
	const actual = gitOutput(['ls-files', '--stage', '-z'])
		.split('\0').filter(Boolean).sort().join('\0');
	if (expected !== actual)
		mismatch();

	// merge-tree uses ref names, not the original merge's marker labels.
	const labels = text => text.replace(
		/^(<+|\|+|>+) [^\r\n]*/gm, '$1');
	const differences = gitOutput(['diff-tree', '--raw', '-r', '-z',
		'--no-renames', '--no-abbrev',
		merge.tree, autoMerge]).split('\0');
	for (let i = 0; i < differences.length - 1; i += 2) {
		const [oldMode, mode, before, after, status] =
			differences[i].split(' ');
		if (oldMode.slice(1) !== mode || status !== 'M' ||
			!paths.has(differences[i + 1]))
			mismatch();
		if (labels(gitOutput(['cat-file', 'blob', before])) !==
			labels(gitOutput(['cat-file', 'blob', after])))
			mismatch();
	}
	withTemporaryIndex(indexGit => {
		indexGit(['read-tree', autoMerge]);
		try {
			indexGit(['update-index', '--refresh']);
		} catch (error) {
			if (error.status !== 1)
				throw error;
			mismatch();
		}
	});
}

function resolveMerge() {
	const head = git('rev-parse', 'HEAD');
	const mergeHeadFile = git('rev-parse', '--git-path', 'MERGE_HEAD');
	const mergeHead = fs.readFileSync(mergeHeadFile, 'utf8').trim();
	if (mergeHead.includes('\n'))
		throw new Error('Only two-parent merges are supported');
	const merge = mergeTree('HEAD', 'MERGE_HEAD');
	const autoMerge = git('rev-parse', '--verify', 'AUTO_MERGE^{tree}');
	validateMerge(merge, autoMerge);
	const pinningSubject = pinningMessage.split('\n')[0];
	const pinningCommits = git('log', '--topo-order', '--no-merges',
		'--format=%H%x00%s', `--grep=^${pinningSubject}$`,
		'HEAD', '--not', 'MERGE_HEAD', '--')
		.split('\n').map(line => line.split('\0'))
		.filter(([, subject]) => subject === pinningSubject)
		.map(([commit]) => commit);
	if (!pinningCommits.length)
		throw new Error('Cannot find downstream Action pinning commit');
	let tree = 'HEAD';
	for (const commit of pinningCommits) {
		const reverted = mergeTree(`--merge-base=${commit}`,
			tree, `${commit}^`);
		if (!reverted.clean)
			throw new Error('Cannot cleanly revert ' +
				'Action pinning commit ' + commit);
		tree = reverted.tree;
	}
	// Preserve HEAD's ancestry, including multiple possible merge bases.
	const unpinned = git('commit-tree', tree, '-p', 'HEAD',
		'-m', 'Unpin GitHub Actions for merge-tree');
	const remerged = mergeTree(unpinned, 'MERGE_HEAD');
	if (!remerged.clean)
		throw new Error('Merge still has conflicts ' +
			'without Action pins');
	const changed = pinWorkflows(remerged.tree);
	withTemporaryIndex((indexGit, temporaryIndex) => {
		indexGit(['read-tree', remerged.tree]);
		for (const [file, text] of changed) {
			const mode = indexGit(['ls-files', '--stage',
				'--', file]).split(' ')[0];
			const blob = gitOutput(['hash-object', '-w', '--stdin'],
				{ input: text }).trim();
			indexGit(['update-index', '--cacheinfo',
				mode, blob, file]);
		}
		const resolution = indexGit(['write-tree']).trim();
		indexGit(['read-tree', autoMerge]);
		indexGit(['update-index', '--refresh']);
		const index = path.resolve(
			git('rev-parse', '--git-path', 'index'));
		const lock = `${index}.lock`;
		fs.copyFileSync(temporaryIndex, lock,
			fs.constants.COPYFILE_EXCL);
		try {
			const currentMergeHead = fs.readFileSync(
				mergeHeadFile, 'utf8').trim();
			if (git('rev-parse', 'HEAD') !== head ||
				currentMergeHead !== mergeHead)
				throw new Error('Merge changed while ' +
					'resolving Action pins');
			validateMerge(merge, autoMerge);

			// Read from the lock so Git can atomically install the
			// index while retaining its worktree safety checks.
			gitOutput(['read-tree', '-m', '-u',
				`--index-output=${index}`,
				autoMerge, resolution], {
				env: { ...process.env, GIT_INDEX_FILE: lock }
			});
		} finally {
			fs.unlinkSync(lock);
		}
	});
	console.log('Resolved merge conflicts with refreshed Action pins.');
}

function main() {
	process.chdir(git('rev-parse', '--show-toplevel'));
	if (fs.existsSync(git('rev-parse', '--git-path', 'MERGE_HEAD'))) {
		resolveMerge();
		return;
	}
	if (git('status', '--porcelain', '--untracked-files=no',
		'--', '.github/workflows'))
		throw new Error('Workflow files have uncommitted changes');
	const changed = pinWorkflows();
	if (changed.length) {
		const message = git('rev-parse', '--git-path',
			'COMMIT_EDITMSG');
		fs.writeFileSync(message, pinningMessage);
		for (const [file, text] of changed)
			fs.writeFileSync(file, text);
		console.log(git('commit', '--signoff', '-F', message,
			'--', ...changed.map(([file]) => file)));
	} else {
		console.log('Action pins are up to date.');
	}
}

try {
	main();
} catch (error) {
	console.error(`error: ${error.message}`);
	process.exitCode = 1;
}
