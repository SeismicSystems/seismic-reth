const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const { resolve } = require('node:path');
const test = require('node:test');

test('nightly tag move is gated on a successful release job', () => {
    const workflowPath = resolve(__dirname, '../workflows/seismic-release.yml');
    const workflow = readFileSync(workflowPath, 'utf8');

    assert.match(
        workflow,
        /- name: Move nightly tag\n\s+if: \$\{\{ env\.IS_NIGHTLY == 'true' && needs\.release\.result == 'success' \}\}/
    );
});
