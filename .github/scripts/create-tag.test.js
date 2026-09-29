const assert = require('node:assert/strict');
const test = require('node:test');

const createTag = require('./create-tag.js');

const context = {
    repo: {
        owner: 'SeismicSystems',
        repo: 'seismic-reth',
    },
    sha: 'abc123',
};

function githubWithGit(overrides) {
    return {
        rest: {
            git: {
                createRef: async () => undefined,
                getRef: async () => ({ data: { object: { sha: context.sha } } }),
                ...overrides,
            },
        },
    };
}

test('createTag creates a new ref for the requested tag', async () => {
    const calls = [];
    const github = githubWithGit({
        createRef: async args => {
            calls.push(args);
        },
    });

    await createTag({ github, context }, 'nightly-abc123');

    assert.deepEqual(calls, [
        {
            owner: 'SeismicSystems',
            repo: 'seismic-reth',
            ref: 'refs/tags/nightly-abc123',
            sha: 'abc123',
        },
    ]);
});

test('createTag treats an existing same-SHA tag as idempotent', async () => {
    let checkedRef;
    const github = githubWithGit({
        createRef: async () => {
            const err = new Error('Reference already exists');
            err.status = 422;
            throw err;
        },
        getRef: async args => {
            checkedRef = args.ref;
            return { data: { object: { sha: context.sha } } };
        },
    });

    await createTag({ github, context }, 'nightly-abc123');

    assert.equal(checkedRef, 'tags/nightly-abc123');
});

test('createTag rejects an existing tag that points at another SHA', async () => {
    const github = githubWithGit({
        createRef: async () => {
            const err = new Error('Reference already exists');
            err.status = 422;
            throw err;
        },
        getRef: async () => ({ data: { object: { sha: 'def456' } } }),
    });

    await assert.rejects(
        createTag({ github, context }, 'nightly-abc123'),
        /already exists at def456, expected abc123/
    );
});

test('createTag propagates non-idempotent create failures', async () => {
    const github = githubWithGit({
        createRef: async () => {
            const err = new Error('GitHub API unavailable');
            err.status = 500;
            throw err;
        },
    });

    await assert.rejects(
        createTag({ github, context }, 'nightly-abc123'),
        /GitHub API unavailable/
    );
});

test('createTag propagates non-existing-reference validation failures', async () => {
    const github = githubWithGit({
        createRef: async () => {
            const err = new Error('Invalid sha');
            err.status = 422;
            throw err;
        },
    });

    await assert.rejects(
        createTag({ github, context }, 'nightly-abc123'),
        /Invalid sha/
    );
});
