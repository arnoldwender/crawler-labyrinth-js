export { buildBaitLinks, renderCrawlerBaitHtml } from './bait.js';
export {
  DEFAULT_ROUTE_PREFIX,
  DEFAULT_SECRET,
  formatTrapPath,
  getActiveLabyrinthConfig,
  isTrainingOnlyUserAgent,
  normalizeBasePath,
  resolveConfig,
  sanitizeBurstLimit,
  sanitizeRoutePrefix,
  sanitizeSeed,
  sanitizeTrailingSlash,
  setActiveLabyrinthConfig,
} from './config.js';
export {
  hashClientIp,
  hmacSha256Hex,
  normalizeClientIp,
  signTrapToken,
  timingSafeEqualHex,
  verifyTrapToken,
} from './crypto.js';
export { createEdgeLabyrinthHandler, createLabyrinthHandler } from './edge.js';
export type { EdgeLabyrinthHandler, LabyrinthHandler } from './edge.js';
export { generateDecoyDocument } from './generator.js';
export type { GenerateDecoyParams } from './generator.js';
export { QuarantineStore } from './quarantine.js';
export { patchRobotsTxt, stripTrapFromSitemapXml } from './robots.js';
export type { PatchRobotsOptions } from './robots.js';
export type {
  BaitLink,
  BaitOptions,
  DecoyDocument,
  EdgeLabyrinthOptions,
  EntryVector,
  LabyrinthOptions,
  ResolvedLabyrinthConfig,
  ResponseFormat,
  TrailingSlashMode,
  TrapMode,
  TrapViolationEvent,
} from './types.js';
