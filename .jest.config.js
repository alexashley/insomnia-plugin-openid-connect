module.exports = {
    collectCoverageFrom: ['src/**/*.js'],
    coverageDirectory: '.jest/coverage',
    cacheDirectory: '.jest/cache',
    coverageThreshold: {
        global: {
            branches: 100,
            functions: 100,
            lines: 100,
            statements: 100,
        },
    },
};
