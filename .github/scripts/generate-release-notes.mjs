#!/usr/bin/env node
import {execSync, exec} from 'node:child_process';
import {promisify} from 'node:util';

const execAsync = promisify(exec);

const BLOCK_TAGS = ['PR', 'BREAKING CHANGE'];

const prevTag = execSync("git tag --sort=-version:refname | grep '^version/' | head -1", {shell: true})
    .toString().trim();

const range = prevTag ? `${prevTag}..HEAD` : 'HEAD';
const rawCommits = execSync(`git log ${range} --pretty=format:"%H"`, {shell: true})
    .toString().trim().split('\n').filter(Boolean);

function extractBlock(text, tag) {
    const pattern = new RegExp(`^\\s*${tag}:(.*)$`, 'm');
    const match = text.match(pattern);
    if (!match) {
        return {value: null, remaining: text};
    }
    const start = match.index;
    const afterTag = text.slice(start + match[0].length);
    const nextBlockPattern = new RegExp(`^\\s*(?:${BLOCK_TAGS.map(t => `${t}:`).join('|')})`, 'm');
    const nextBlock = afterTag.search(nextBlockPattern);
    const blockContent = nextBlock === -1 ? afterTag : afterTag.slice(0, nextBlock);
    const value = (match[1] + blockContent).trim();
    const remaining = text.slice(0, start) + (nextBlock === -1 ? '' : afterTag.slice(nextBlock));
    return {value, remaining: remaining.trimEnd()};
}

async function parseCommit(hash) {
    const {stdout} = await execAsync(`git show ${hash} --pretty=format:"%s%n%n%b" --no-patch`);
    const raw = stdout.trim();

    const [subject, ...rest] = raw.split('\n');
    let bodyLines = rest.join('\n').trimStart();

    const {value: pr, remaining: afterPr} = extractBlock(bodyLines, 'PR');
    const {value: breakingChange, remaining: body} = extractBlock(afterPr, 'BREAKING CHANGE');

    return {subject, body: body.trimEnd(), pr, breakingChange};
}

function formatEntry({subject, body, pr, breakingChange}) {
    const suffix = pr ? ` (${pr})` : '';
    let entry = `* **${subject}${suffix}**`;
    if (body) {
        entry += '\n\n' + body.split('\n').map(l => `  ${l}`).join('\n');
    }
    if (breakingChange) {
        const quoted = breakingChange.split('\n').map(l => `> ${l}`).join('\n');
        entry += '\n\n  > **BREAKING CHANGE**\n  >\n' + quoted.split('\n').map(l => `  ${l}`).join('\n');
    }
    return entry;
}

const commits = await Promise.all(rawCommits.map(parseCommit));

const groups = {major: [], minor: [], patch: []};

for (const {subject, body, pr, breakingChange} of commits) {
    let group = null;
    if (subject.startsWith('MAJOR:')) {
        group = 'major';
    } else if (subject.startsWith('MINOR:')) {
        group = 'minor';
    } else if (subject.startsWith('PATCH:')) {
        group = 'patch';
    } else {
        continue;
    }

    const title = subject.slice(subject.indexOf(':') + 1).trim();
    const entry = formatEntry({subject: title, body, pr, breakingChange});
    groups[group].push(entry);
}

let notes = '';
if (groups.major.length) {
    notes += `## Major Changes\n\n${groups.major.join('\n\n')}\n\n`;
}
if (groups.minor.length) {
    notes += `## Minor Changes\n\n${groups.minor.join('\n\n')}\n\n`;
}
if (groups.patch.length) {
    notes += `## Patch Changes\n\n${groups.patch.join('\n\n')}\n\n`;
}

process.stdout.write(notes.trimEnd() + '\n');
