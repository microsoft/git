#!/usr/bin/env node

const { execFileSync } = require('node:child_process');
const fs = require('node:fs');

const pinningMessage = `ci: pin GitHub Actions to satisfy downstream policy

Microsoft Git inherits workflows that upstream maintains using symbolic
Action refs. Downstream organizational policy requires full commit IDs
instead, adding pin maintenance to this project's maintainers' workload.

Keep pins aligned with the original upstream Action refs in a fresh
downstream snapshot, independent of any earlier pinning commit.
`;

function git(...args) {
	return execFileSync('git', ['--no-pager', ...args], {
		encoding: 'utf8',
		stdio: ['ignore', 'pipe', 'pipe'],
		maxBuffer: 16 * 1024 * 1024
	}).trim();
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

function readWorkflow(file) {
	const text = fs.readFileSync(file, 'utf8');
	const parts = text.split(/(^ *-? *uses:[^\r\n]*)/m);
	const matches = parts.map(part => part.match(useLine))
		.filter(use => use && !use[3].startsWith('./'));
	const workflowHistory = matches.some(use => isSHA(use[4]))
		? git('log', '--follow', '-p', '-U0',
			'-Guses:.*@', '--no-ext-diff', '--no-textconv',
			'--format=%x00', '--', file)
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

try {
	process.chdir(git('rev-parse', '--show-toplevel'));
	const files = git('ls-files', '-z', '--', '.github/workflows')
		.split('\0').filter(file => /\.ya?ml$/.test(file));
	if (git('status', '--porcelain', '--untracked-files=no',
		'--', '.github/workflows'))
		throw new Error('Workflow files have uncommitted changes');
	const workflows = files.map(readWorkflow);
	const actionRefs = workflows.flatMap(workflow => workflow.actionRefs);
	const uniquePins = new Map(actionRefs.map(actionRef =>
		[actionRef.pinKey, actionRef]));
	const pins = Object.fromEntries([...uniquePins.values()].map(
		({ pinKey, actionName, version }) =>
			[pinKey, resolveActionSHA(actionName, version)]));
	const changed = workflows.map(workflow => substitute(workflow, pins))
		.filter(Boolean);
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
} catch (error) {
	console.error(`error: ${error.message}`);
	process.exitCode = 1;
}
