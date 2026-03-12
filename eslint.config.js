import js from '@eslint/js';
import stylistic from '@stylistic/eslint-plugin';
import TypeScriptESLint from '@typescript-eslint/eslint-plugin';
import parser from '@typescript-eslint/parser';
import eslintPluginImport from 'eslint-plugin-import';
import eslintPluginPerfectionist from 'eslint-plugin-perfectionist';
import globals from 'globals';
import path from 'node:path';
import {fileURLToPath} from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const commonRules = {
    ...js.configs.recommended.rules,
    ...(eslintPluginImport.flatConfigs.recommended?.rules ?? eslintPluginImport.flatConfigs.recommended),
    ...eslintPluginPerfectionist.configs['recommended-natural'].rules,
    'comma-dangle': [2, {
        arrays   : 'always-multiline',
        exports  : 'never',
        functions: 'never',
        imports  : 'never',
        objects  : 'always-multiline',
    }],
    'comma-spacing'       : [2, {after: true, before: false}],
    'eol-last'            : 2,
    'func-style'          : [2, 'expression'],
    'import/no-unresolved': 0,
    'key-spacing'         : [2, {align: 'colon'}],
    'new-cap'             : [2, {capIsNew: false}],
    'no-multi-spaces'     : [2, {exceptions: {Property: true, TSPropertySignature: true}}],
    'no-trailing-spaces'  : 2,
    'no-unused-vars'      : 0,
    'object-curly-newline': [2, {
        ObjectExpression: {
            consistent: true, minProperties: 0, multiline: true,
        },
        ObjectPattern: {
            consistent: true, minProperties: 0, multiline: true,
        },
    }],
    'object-curly-spacing' : [2, 'never'],
    'object-shorthand'     : [2, 'always'],
    'prefer-arrow-callback': 2,
    'prefer-template'      : 2,
    'quote-props'          : [2, 'as-needed'],
    quotes                 : [2, 'single'],
    semi                   : 2,
};

const typescriptRules = {
    ...(TypeScriptESLint.configs.eslintRecommended?.rules ?? TypeScriptESLint.configs.eslintRecommended),
    ...(TypeScriptESLint.configs.recommendedTypeChecked?.rules ?? TypeScriptESLint.configs.recommendedTypeChecked),
    ...(TypeScriptESLint.configs.strictTypeChecked?.rules ?? TypeScriptESLint.configs.strictTypeChecked),
    ...(eslintPluginImport.flatConfigs.typescript?.rules ?? eslintPluginImport.flatConfigs.typescript),
    '@stylistic/indent'                               : [2, 4],
    '@typescript-eslint/consistent-type-definitions'  : 2,
    '@typescript-eslint/consistent-type-exports'      : 2,
    '@typescript-eslint/consistent-type-imports'      : 2,
    '@typescript-eslint/explicit-function-return-type': [2, {
        allowConciseArrowFunctionExpressionsStartingWithVoid: true,
        allowDirectConstAssertionInArrowFunctions           : true,
    }],
    '@typescript-eslint/naming-convention'           : 0,
    '@typescript-eslint/no-explicit-any'             : 0,
    '@typescript-eslint/no-extraneous-class'         : [2, {allowWithDecorator: true}],
    '@typescript-eslint/no-non-null-assertion'       : 1,
    '@typescript-eslint/no-unsafe-assignment'        : 1,
    '@typescript-eslint/no-unsafe-call'              : 1,
    '@typescript-eslint/no-unused-expressions'       : [2, {allowTernary: true}],
    '@typescript-eslint/no-unused-vars'              : [2, {argsIgnorePattern: '^_', varsIgnorePattern: '^_'}],
    '@typescript-eslint/no-use-before-define'        : 0,
    '@typescript-eslint/prefer-nullish-coalescing'   : 2,
    '@typescript-eslint/prefer-reduce-type-parameter': 0,
    '@typescript-eslint/promise-function-async'      : 2,
    '@typescript-eslint/return-await'                : [2, 'always'],
    'no-return-await'                                : 0,
    'no-unused-expressions'                          : 0,
    'no-use-before-define'                           : 0,
};

export default [
    {
        ignores: ['dist/**', 'node_modules/**'],
    },
    {
        files          : ['remote-ui/**/*.js'],
        languageOptions: {
            globals      : {...globals.browser, ...globals.es2021},
            parserOptions: {ecmaVersion: 'latest', sourceType: 'module'},
        },
        plugins: {
            '@stylistic' : stylistic,
            import       : eslintPluginImport,
            perfectionist: eslintPluginPerfectionist,
        },
        rules: {...commonRules},
    },
    {
        files          : ['**/*.js', '**/*.mjs'],
        ignores        : ['dist/**', 'node_modules/**', 'remote-ui/**'],
        languageOptions: {
            globals      : {...globals.node, ...globals.es2021},
            parserOptions: {ecmaVersion: 'latest', sourceType: 'module'},
        },
        plugins: {
            '@stylistic' : stylistic,
            import       : eslintPluginImport,
            perfectionist: eslintPluginPerfectionist,
        },
        rules: {...commonRules},
    },
    {
        files          : ['**/*.ts'],
        ignores        : ['dist/**', 'node_modules/**'],
        languageOptions: {
            globals      : {...globals.node, ...globals.es2021},
            parser,
            parserOptions: {
                ecmaFeatures   : {modules: true},
                ecmaVersion    : 'latest',
                project        : 'tsconfig.eslint.json',
                sourceType     : 'module',
                tsconfigRootDir: __dirname,
            },
        },
        plugins: {
            '@stylistic'        : stylistic,
            '@typescript-eslint': TypeScriptESLint,
            import              : eslintPluginImport,
            perfectionist       : eslintPluginPerfectionist,
        },
        rules: {...commonRules, ...typescriptRules},
    },
];
