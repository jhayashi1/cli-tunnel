import {defineConfig} from 'vitest/config';

export default defineConfig({
    test: {
        coverage: {
            exclude : ['src/**/*.test.ts'],
            include : ['src/**/*.ts'],
            provider: 'v8',
            reporter: ['text', 'lcov'],
        },
        hookTimeout: 30000,
        testTimeout: 30000,
    },
});
