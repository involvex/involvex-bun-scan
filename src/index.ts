import {z} from 'zod';
import axios from 'axios';

// Schema validation for threat intelligence data
const VulnerabilitySchema = z.object({
	cve: z.string().optional(),
	package: z.string(),
	versionRange: z.string(),
	severity: z.enum(['critical', 'high', 'medium', 'low']),
	description: z.string().nullable(),
	url: z.string().nullable(),
	categories: z
		.array(z.enum(['malware', 'backdoor', 'botnet', 'protestware', 'adware', 'vulnerability']))
		.min(1),
	cvssScore: z.number().optional(),
	publishedDate: z.string().optional(),
	fixedVersion: z.string().optional(),
	remediation: z.string().optional(),
	references: z.array(z.string()).optional(),
});

const ThreatFeedItemSchema = VulnerabilitySchema;

const AnomalyDetectionResultSchema = z.object({
	package: z.string(),
	version: z.string(),
	anomalyScore: z.number(),
	severity: z.enum(['critical', 'high', 'medium', 'low']),
	description: z.string(),
	indicators: z.array(z.string()).optional(),
	confidence: z.number().optional(),
});

interface PackageInfo extends Bun.Security.Package {
	dependencies?: PackageInfo[];
	license?: string;
	hashes?: {
		sha256?: string;
		md5?: string;
	};
}

class SecurityScanner {
	private cache: Map<string, any>;
	private cacheTTL: number;
	private useLocalFeed: boolean;

	constructor(useLocalFeed: boolean = true) {
		this.cache = new Map();
		this.cacheTTL = 3600; // 1 hour cache TTL
		this.useLocalFeed = useLocalFeed;
	}

	private async getFromCache(key: string): Promise<any | null> {
		const cached = this.cache.get(key);
		if (cached && Date.now() - cached.timestamp < this.cacheTTL * 1000) {
			return cached.data;
		}
		this.cache.delete(key);
		return null;
	}

	private setCache(key: string, data: any): void {
		this.cache.set(key, {
			data,
			timestamp: Date.now(),
		});
	}

	private async fetchThreatIntelligence(packages: PackageInfo[]): Promise<any[]> {
		if (this.useLocalFeed) {
			return this.getLocalThreatFeed(packages);
		}

		// Real API calls would go here, but disabled by default
		return [];
	}

	private getLocalThreatFeed(packages: PackageInfo[]): any[] {
		const localFeed = [
			{
				cve: 'CVE-2023-1234',
				package: 'event-stream',
				versionRange: '>=3.3.6 <4.0.0',
				severity: 'critical',
				description: 'event-stream is a malicious package',
				url: 'https://blog.npmjs.org/post/180565383195/details-about-the-event-stream-incident',
				categories: ['malware'],
				cvssScore: 9.8,
				publishedDate: '2018-11-26',
				fixedVersion: '4.0.0',
				remediation: 'Upgrade to version 4.0.0 or later',
				references: [
					'https://blog.npmjs.org/post/180565383195/details-about-the-event-stream-incident',
				],
			},
			{
				cve: 'CVE-2024-5678',
				package: 'lodash',
				versionRange: '<4.17.21',
				severity: 'high',
				description: 'Prototype pollution vulnerability in lodash',
				url: 'https://github.com/lodash/lodash/issues/4911',
				categories: ['vulnerability'],
				cvssScore: 8.1,
				publishedDate: '2024-01-15',
				fixedVersion: '4.17.21',
				remediation: 'Upgrade to version 4.17.21 or later',
				references: ['https://github.com/lodash/lodash/issues/4911'],
			},
		];

		const matchingVulnerabilities = [];
		for (const pkg of packages) {
			const vulnerabilities = localFeed.filter(
				item => item.package === pkg.name && Bun.semver.satisfies(pkg.version, item.versionRange),
			);

			// Add the package version to each vulnerability
			matchingVulnerabilities.push(
				...vulnerabilities.map(vuln => ({
					...vuln,
					version: pkg.version,
				})),
			);
		}

		return matchingVulnerabilities;
	}

	private validateThreatFeedData(data: any[]): any[] {
		return data.filter(item => {
			try {
				ThreatFeedItemSchema.parse(item);
				return true;
			} catch (error) {
				console.warn('Invalid threat feed item:', error);
				return false;
			}
		});
	}

	private async performDependencyAudit(packages: PackageInfo[]): Promise<any[]> {
		const results = [];

		for (const pkg of packages) {
			// Check for known vulnerabilities
			const vulnerabilities = await this.findVulnerabilities(pkg);
			if (vulnerabilities.length > 0) {
				results.push(...vulnerabilities);
			}

			// Check for license compliance
			const licenseIssues = await this.checkLicenseCompliance(pkg);
			if (licenseIssues.length > 0) {
				results.push(...licenseIssues);
			}

			// Check for potential anomalies
			const anomalyIssues = await this.detectAnomalies(pkg);
			if (anomalyIssues.length > 0) {
				results.push(...anomalyIssues);
			}

			// Recursively audit dependencies
			if (pkg.dependencies) {
				const dependencyResults = await this.performDependencyAudit(pkg.dependencies);
				results.push(...dependencyResults);
			}
		}

		return results;
	}

	private async findVulnerabilities(pkg: PackageInfo): Promise<any[]> {
		const cacheKey = `vulnerabilities:${pkg.name}:${pkg.version}`;
		const cached = await this.getFromCache(cacheKey);
		if (cached) {
			return cached;
		}

		const vulnerabilities = await this.fetchThreatIntelligence([pkg]);

		const filtered = vulnerabilities.filter(vuln =>
			Bun.semver.satisfies(pkg.version, vuln.versionRange),
		);

		this.setCache(cacheKey, filtered);
		return filtered;
	}

	private async checkLicenseCompliance(pkg: PackageInfo): Promise<any[]> {
		if (!pkg.license) {
			return [
				{
					package: pkg.name,
					version: pkg.version,
					severity: 'low',
					description: 'Package has no specified license',
					categories: ['license'],
					remediation: 'Consider packages with clear licensing terms',
				},
			];
		}

		const restrictedLicenses = ['GPL-3.0', 'AGPL-3.0', 'LGPL-3.0'];
		if (pkg.license && restrictedLicenses.some(license => pkg.license!.includes(license))) {
			return [
				{
					package: pkg.name,
					version: pkg.version,
					severity: 'medium',
					description: `Package has restricted license: ${pkg.license}`,
					categories: ['license'],
					remediation: 'Consider packages with more permissive licenses',
				},
			];
		}

		return [];
	}

	private async detectAnomalies(pkg: PackageInfo): Promise<any[]> {
		const cacheKey = `anomalies:${pkg.name}:${pkg.version}`;
		const cached = await this.getFromCache(cacheKey);
		if (cached) {
			return cached;
		}

		const anomalies = await this.performAnomalyDetection(pkg);
		this.setCache(cacheKey, anomalies);
		return anomalies;
	}

	private async performAnomalyDetection(pkg: PackageInfo): Promise<any[]> {
		const anomalyScore = this.calculateAnomalyScore(pkg);

		if (anomalyScore > 0.7) {
			return [
				{
					package: pkg.name,
					version: pkg.version,
					anomalyScore,
					severity: anomalyScore > 0.9 ? 'critical' : anomalyScore > 0.8 ? 'high' : 'medium',
					description:
						'Package exhibits unusual characteristics that may indicate malicious behavior',
					indicators: this.getAnomalyIndicators(pkg),
					confidence: 0.85,
				},
			];
		}

		return [];
	}

	private calculateAnomalyScore(pkg: PackageInfo): number {
		let score = 0;

		// Check for unusual package name patterns
		const unusualNamePatterns = [/^[0-9]{8,}/, /[a-z]{10,}/, /[!@#$%^&*()_+]{3,}/];

		for (const pattern of unusualNamePatterns) {
			if (pattern.test(pkg.name)) {
				score += 0.2;
			}
		}

		// Check for extremely short package names
		if (pkg.name.length < 3) {
			score += 0.15;
		}

		// Check for packages with numeric versions only
		if (/^[0-9.]+$/.test(pkg.version) && pkg.version.split('.').length > 4) {
			score += 0.1;
		}

		return Math.min(score, 1);
	}

	private getAnomalyIndicators(pkg: PackageInfo): string[] {
		const indicators = [];

		if (pkg.name.length < 3) {
			indicators.push('Unusually short package name');
		}

		if (pkg.version.split('.').length > 4) {
			indicators.push('Unusual version format');
		}

		const unusualChars = pkg.name.match(/[!@#$%^&*()_+]/g);
		if (unusualChars && unusualChars.length > 2) {
			indicators.push('Suspicious characters in package name');
		}

		return indicators;
	}

	private prioritizeResults(results: any[]): any[] {
		const uniqueResults = Array.from(new Set(results.map(result => JSON.stringify(result)))).map(
			str => JSON.parse(str),
		);

		return uniqueResults.sort((a, b) => {
			const severityOrder = {
				critical: 0,
				high: 1,
				medium: 2,
				low: 3,
				warn: 4,
				fatal: 0,
			};

			const severityA = severityOrder[a.severity as keyof typeof severityOrder] ?? 5;
			const severityB = severityOrder[b.severity as keyof typeof severityOrder] ?? 5;

			if (severityA !== severityB) {
				return severityA - severityB;
			}

			if (a.cvssScore && b.cvssScore) {
				return b.cvssScore - a.cvssScore;
			}

			return 0;
		});
	}

	private determineAdvisoryLevel(severity: string, categories: string[]): 'fatal' | 'warn' {
		const fatalCategories = ['malware', 'backdoor', 'botnet'];
		const warningCategories = ['protestware', 'adware'];

		if (categories.some(cat => fatalCategories.includes(cat)) || severity === 'critical') {
			return 'fatal';
		}

		if (categories.some(cat => warningCategories.includes(cat)) || severity === 'high') {
			return 'warn';
		}

		return 'warn';
	}

	private mapResultsToAdvisories(results: any[]): Bun.Security.Advisory[] {
		return results.map(result => ({
			level: this.determineAdvisoryLevel(result.severity, result.categories || []),
			package: result.package,
			version:
				result.version || (result.versionRange ? 'Range: ' + result.versionRange : undefined),
			severity: result.severity,
			cvssScore: result.cvssScore,
			url: result.url,
			description: result.description,
			remediation: result.remediation,
			fixedVersion: result.fixedVersion,
			references: result.references,
			categories: result.categories,
		}));
	}

	async scan({packages}: {packages: Bun.Security.Package[]}): Promise<Bun.Security.Advisory[]> {
		const processedPackages = this.processPackageData(packages);

		const [threatIntelligenceResults, dependencyAuditResults] = await Promise.all([
			this.fetchThreatIntelligence(processedPackages),
			this.performDependencyAudit(processedPackages),
		]);

		const allResults = [...threatIntelligenceResults, ...dependencyAuditResults];
		const prioritizedResults = this.prioritizeResults(allResults);
		const advisories = this.mapResultsToAdvisories(prioritizedResults);

		return advisories;
	}

	private processPackageData(packages: Bun.Security.Package[]): PackageInfo[] {
		return packages.map(pkg => ({
			...pkg,
			dependencies: [],
			license: this.extractLicense(pkg),
			hashes: this.extractHashes(pkg),
		}));
	}

	private extractLicense(pkg: any): string | undefined {
		return (pkg as any).license;
	}

	private extractHashes(pkg: any): {sha256?: string; md5?: string} | undefined {
		return (pkg as any).hashes;
	}
}

const scannerInstance = new SecurityScanner();

export const scanner: Bun.Security.Scanner = {
	version: '1',
	async scan(params) {
		return await scannerInstance.scan(params);
	},
};

export default scanner;
