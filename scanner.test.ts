import {expect, test} from 'bun:test';
import {scanner} from './src/index.ts';

test('Scanner should warn about known malicious packages', async () => {
	const advisories = await scanner.scan({
		packages: [
			{
				name: 'event-stream',
				version: '3.3.6',
				requestedRange: '^3.3.0',
				tarball: 'https://registry.npmjs.org/event-stream/-/event-stream-3.3.6.tgz',
				license: 'MIT',
			},
		],
	});

	expect(advisories.length).toBeGreaterThan(0);

	const eventStreamAdvisory = advisories.find(a => a.package === 'event-stream');
	expect(eventStreamAdvisory).toBeDefined();
	expect(eventStreamAdvisory?.level).toBe('fatal');
});

test('There should be no advisories if no packages are being installed', async () => {
	const advisories = await scanner.scan({packages: []});
	expect(advisories.length).toBe(0);
});

test('Should handle packages without specified licenses', async () => {
	const advisories = await scanner.scan({
		packages: [
			{
				name: 'unlicensed-package',
				version: '1.0.0',
				requestedRange: '^1.0.0',
				tarball: 'https://registry.npmjs.org/unlicensed-package/-/unlicensed-package-1.0.0.tgz',
			},
		],
	});

	const licenseAdvisory = advisories.find(a =>
		a.description?.includes('Package has no specified license'),
	);

	expect(licenseAdvisory).toBeDefined();
	expect(licenseAdvisory?.level).toBe('warn');
});

test('Should handle scoped packages correctly', async () => {
	const advisories = await scanner.scan({
		packages: [
			{
				name: '@types/node',
				version: '20.0.0',
				requestedRange: '^20.0.0',
				tarball: 'https://registry.npmjs.org/@types/node/-/node-20.0.0.tgz',
				license: 'MIT',
			},
		],
	});

	const licenseAdvisories = advisories.filter(a =>
		a.description?.includes('Package has no specified license'),
	);

	expect(licenseAdvisories.length).toBe(0);
});

test('Should detect vulnerabilities in lodash versions before 4.17.21', async () => {
	const advisories = await scanner.scan({
		packages: [
			{
				name: 'lodash',
				version: '4.17.20',
				requestedRange: '^4.17.0',
				tarball: 'https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz',
				license: 'MIT',
			},
		],
	});

	const lodashAdvisory = advisories.find(a => a.package === 'lodash');
	expect(lodashAdvisory).toBeDefined();
	expect(lodashAdvisory?.level).toBe('warn');
});

test('Should not detect vulnerabilities in lodash 4.17.21 or later', async () => {
	const advisories = await scanner.scan({
		packages: [
			{
				name: 'lodash',
				version: '4.17.21',
				requestedRange: '^4.17.0',
				tarball: 'https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz',
				license: 'MIT',
			},
		],
	});

	const lodashAdvisory = advisories.find(a => a.package === 'lodash');
	expect(lodashAdvisory).toBeUndefined();
});

test('Should prioritize critical vulnerabilities first', async () => {
	const advisories = await scanner.scan({
		packages: [
			{
				name: 'event-stream',
				version: '3.3.6',
				requestedRange: '^3.3.0',
				tarball: 'https://registry.npmjs.org/event-stream/-/event-stream-3.3.6.tgz',
				license: 'MIT',
			},
			{
				name: 'lodash',
				version: '4.17.20',
				requestedRange: '^4.17.0',
				tarball: 'https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz',
				license: 'MIT',
			},
		],
	});

	expect(advisories.length).toBeGreaterThan(1);
	expect(advisories[0]?.level).toBe('fatal');
	expect(advisories[0]?.package).toBe('event-stream');
	expect(advisories[1]?.level).toBe('warn');
	expect(advisories[1]?.package).toBe('lodash');
});

test('Should return advisories with detailed information', async () => {
	const advisories = await scanner.scan({
		packages: [
			{
				name: 'event-stream',
				version: '3.3.6',
				requestedRange: '^3.3.0',
				tarball: 'https://registry.npmjs.org/event-stream/-/event-stream-3.3.6.tgz',
				license: 'MIT',
			},
		],
	});

	const advisory = advisories[0];
	expect(advisory).toBeDefined();
	expect(advisory?.package).toBe('event-stream');
	expect(advisory?.description).toBeDefined();
	expect(advisory?.url).toBeDefined();
});

test('Should handle multiple packages with mixed security status', async () => {
	const advisories = await scanner.scan({
		packages: [
			{
				name: 'event-stream',
				version: '3.3.6',
				requestedRange: '^3.3.0',
				tarball: 'https://registry.npmjs.org/event-stream/-/event-stream-3.3.6.tgz',
				license: 'MIT',
			},
			{
				name: 'lodash',
				version: '4.17.21',
				requestedRange: '^4.17.0',
				tarball: 'https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz',
				license: 'MIT',
			},
		],
	});

	expect(advisories.length).toBeGreaterThan(0);

	const eventStreamAdvisory = advisories.find(a => a.package === 'event-stream');
	expect(eventStreamAdvisory).toBeDefined();

	const lodashAdvisory = advisories.find(a => a.package === 'lodash');
	expect(lodashAdvisory).toBeUndefined();
});
