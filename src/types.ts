import type { QuarantineStore } from './quarantine.js';

export type TrapMode = 'hybrid' | 'labyrinth' | 'block' | 'observe';

export type ResponseFormat = 'html' | 'plain';

export type TrailingSlashMode = 'always' | 'never' | 'ignore';

export type EntryVector = 'signed_bait' | 'robots_probe' | 'ua_guard';

export interface TrapViolationEvent {
  readonly timestamp: string;
  readonly ipDigest: string;
  readonly userAgentExcerpt: string;
  readonly routeToken: string;
  readonly actionTaken: 'decoy_served' | 'quarantined' | 'observed' | 'burst_shed';
  readonly entryVector?: EntryVector;
  readonly strikes: number;
  readonly status: number;
}

export interface LabyrinthOptions {
  readonly routePrefix?: string;
  readonly basePath?: string;
  readonly trailingSlash?: TrailingSlashMode;
  readonly mode?: TrapMode;
  readonly format?: ResponseFormat;
  readonly secret?: string;
  readonly maxDepth?: number;
  readonly linkCount?: number;
  readonly strikeThreshold?: number;
  readonly blockTtlMs?: number;
  readonly blockStatus?: 429 | 403;
  readonly burstLimitPerMinute?: number;
  readonly interceptTrainingBots?: boolean;
  readonly trustProxyHeaders?: boolean;
  readonly trustedProxyHeader?: string;
  readonly entrySeed?: string;
  readonly onViolation?: (event: TrapViolationEvent) => void | Promise<void>;
}

export interface ResolvedLabyrinthConfig {
  readonly routePrefix: string;
  readonly basePath: string;
  readonly trailingSlash: TrailingSlashMode;
  readonly mode: TrapMode;
  readonly format: ResponseFormat;
  readonly secret: string;
  readonly usesDefaultSecret: boolean;
  readonly maxDepth: number;
  readonly linkCount: number;
  readonly strikeThreshold: number;
  readonly blockTtlMs: number;
  readonly blockStatus: 429 | 403;
  readonly burstLimitPerMinute: number;
  readonly interceptTrainingBots: boolean;
  readonly trustProxyHeaders: boolean;
  readonly trustedProxyHeader?: string;
  readonly entrySeed: string;
  readonly onViolation?: (event: TrapViolationEvent) => void | Promise<void>;
}

export interface DecoyDocument {
  readonly status: 200;
  readonly contentType: string;
  readonly title: string;
  readonly entryCode: string;
  readonly depth: number;
  readonly seed: string;
  readonly childTokens: readonly string[];
  readonly body: string;
}

export interface EdgeLabyrinthOptions extends LabyrinthOptions {
  readonly excludedPrefixes?: readonly string[];
  readonly store?: QuarantineStore;
}

export interface BaitOptions {
  readonly routePrefix?: string;
  readonly basePath?: string;
  readonly trailingSlash?: TrailingSlashMode;
  readonly count?: number;
  readonly seed?: string;
  readonly label?: string;
  readonly secret?: string;
}

export interface BaitLink {
  readonly href: string;
  readonly label: string;
  readonly token: string;
}
