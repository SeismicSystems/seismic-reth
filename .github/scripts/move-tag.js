module.exports = async ({ github, context }, tagName) => {
    await github.rest.git.updateRef({
        owner: context.repo.owner,
        repo: context.repo.repo,
        ref: `tags/${tagName}`,
        sha: context.sha,
        force: true,
    });
};
