// Flat-config ESLint for hellojs. CommonJS-only project; we lint for unused vars,
// var/let mistakes, and obvious bugs. Style is enforced by editorconfig + tabs.

module.exports = [
	{
		ignores: ['node_modules/**', 'chrome-response-peet.json', 'leaf*.pem', 'leaf*.der'],
	},
	{
		files: ['**/*.js'],
		languageOptions: {
			ecmaVersion: 2023,
			sourceType: 'commonjs',
			globals: {
				console: 'readonly',
				process: 'readonly',
				Buffer: 'readonly',
				setImmediate: 'readonly',
				setTimeout: 'readonly',
				setInterval: 'readonly',
				clearTimeout: 'readonly',
				clearInterval: 'readonly',
				queueMicrotask: 'readonly',
				require: 'readonly',
				module: 'readonly',
				exports: 'readonly',
				__dirname: 'readonly',
				__filename: 'readonly',
				global: 'readonly',
				URL: 'readonly',
				TextEncoder: 'readonly',
				TextDecoder: 'readonly',
			},
		},
		rules: {
			'no-unused-vars': ['warn', { args: 'none', varsIgnorePattern: '^_' }],
			'no-undef': 'error',
			'no-empty': ['warn', { allowEmptyCatch: true }],
			'no-cond-assign': ['error', 'except-parens'],
			'no-prototype-builtins': 'off',
			'no-constant-condition': ['error', { checkLoops: false }],
			'no-var': 'error',
			'prefer-const': ['warn', { destructuring: 'all' }],
		},
	},
]
