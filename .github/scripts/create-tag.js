function isReferenceAlreadyExistsError(err) {
    return err.status === 422 && /Reference already exists/i.test(err.message);
}

module.exports = async ({ github, context }, tagName) => {
    try {
        await github.rest.git.createRef({
            owner: context.repo.owner,
            repo: context.repo.repo,
            ref: `refs/tags/${tagName}`,
            sha: context.sha,
        });
    } catch (err) {
        if (!isReferenceAlreadyExistsError(err)) {
            console.error(`Failed to create tag: ${tagName}`);
            throw err;
        }

        const existingRef = await github.rest.git.getRef({
            owner: context.repo.owner,
            repo: context.repo.repo,
            ref: `tags/${tagName}`,
        });
        const existingSha = existingRef.data.object.sha;

        if (existingSha !== context.sha) {
            throw new Error(
                `Tag ${tagName} already exists at ${existingSha}, expected ${context.sha}`
            );
        }
    }
};
