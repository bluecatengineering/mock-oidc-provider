import regexpPlugin from 'eslint-plugin-regexp';
import blueCatNode from '@bluecateng/eslint-config-node';

export default [
	blueCatNode,
	regexpPlugin.configs.recommended,
	{
		rules: {
			'jest/no-deprecated-functions': 'off',
		},
	},
	{
		files: ['**/*.js'],
		languageOptions: {
			sourceType: 'commonjs',
		},
	},
	{
		files: ['test/**/*.js'],
		rules: {
			'@bluecateng/no-async': 'off',
		},
	},
	{
		ignores: ['build/**', 'dist/**'],
	},
];
