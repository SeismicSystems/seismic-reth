const assert = require('node:assert/strict');
const test = require('node:test');

const moveTag = require('./move-tag.js');

const context = {
    repo: {
        owner: 'SeismicSystems',
        repo: 'seismic-reth',
    },
    sha: 'abc123',
};

test('moveTag updates the requested tag to the workflow SHA', async () => {
    const calls = [];
    const github = {
        rest: {
            git: {
                updateRef: async args => {
                    calls.push(args);
                },
            },
        },
    };

    await moveTag({ github, context }, 'nightly');

    assert.deepEqual(calls, [
        {
            owner: 'SeismicSystems',
            repo: 'seismic-reth',
            ref: 'tags/nightly',
            sha: 'abc123',
            force: true,
        },
    ]);
});

test('moveTag propagates update failures', async () => {
    const github = {
        rest: {
            git: {
                updateRef: async () => {
                    throw new Error('GitHub API unavailable');
                },
            },
        },
    };

    await assert.rejects(
        moveTag({ github, context }, 'nightly'),
        /GitHub API unavailable/
    );
});
