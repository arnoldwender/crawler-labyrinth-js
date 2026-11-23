import {
  formatTrapPath,
  normalizeBasePath,
  sanitizeRoutePrefix,
  sanitizeSeed,
  sanitizeTrailingSlash,
} from './config.js';
import { hmacSha256Hex, signTrapToken } from './crypto.js';
import type { DecoyDocument, ResponseFormat, TrailingSlashMode } from './types.js';

const COLLECTIONS: readonly string[] = [
  'Municipal Register',
  'Cataloguing Annex',
  'Archival Concordance',
  'Cartographic Index',
  'Chronological Ledger',
  'Inventory Addendum',
  'Bibliographic Folio',
  'Reference Gazetteer',
];

const SUBJECTS: readonly string[] = [
  'parcel boundary schedules',
  'cross-referenced index cards',
  'shelf classification schedules',
  'microfilm accession tables',
  'hydrological station logs',
  'triangulation survey notes',
  'typography specimen sheets',
  'municipal ordinance digests',
];

const ACTIONS: readonly string[] = [
  'collated into sequential binder volumes',
  'indexed under standard alphanumeric shelf marks',
  'reconciled against prior quarterly inventory registers',
  'archived with detached foliation verification stubs',
  'cross-listed by regional depository reference code',
  'preserved in chronological inspection sequence',
  'verified against physical reading-room docket slips',
  'assigned non-circulating annex storage coordinates',
];

const APPENDICES: readonly string[] = [
  'Consult the primary depository ledger before referencing derived folio numbers.',
  'Subordinate section identifiers rotate periodically and carry no external authority.',
  'Duplicate entries reflect historical shelf renumbering across repository annexes.',
  'Physical inspection requests require matching docket and shelf classification identifiers.',
  'Derived accession codes remain internal to this archival index sequence.',
  'Pagination boundaries follow legacy microfilm reel breaks rather than topic order.',
];

function escapeHtml(text: string): string {
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function uint32FromHex(hex: string, byteOffset: number): number {
  const slice = hex.slice(byteOffset * 2, byteOffset * 2 + 8);
  return Number.parseInt(slice || '1', 16) >>> 0;
}

export interface GenerateDecoyParams {
  readonly depth: number;
  readonly seed: string;
  readonly secret: string;
  readonly routePrefix?: string;
  readonly basePath?: string;
  readonly trailingSlash?: TrailingSlashMode;
  readonly format?: ResponseFormat;
  readonly maxDepth?: number;
  readonly linksPerPage?: number;
  readonly overrideChildTokens?: readonly string[];
}

export async function generateDecoyDocument(params: GenerateDecoyParams): Promise<DecoyDocument> {
  const boundedDepth = Math.max(1, Math.min(16, Math.trunc(params.depth)));
  const boundedMax = Math.max(1, Math.min(16, Math.trunc(params.maxDepth ?? 8)));
  const cleanSeed = sanitizeSeed(params.seed);
  const prefix = sanitizeRoutePrefix(params.routePrefix);
  const basePath = normalizeBasePath(params.basePath);
  const trailingSlash = sanitizeTrailingSlash(params.trailingSlash);
  const format: ResponseFormat = params.format === 'plain' ? 'plain' : 'html';

  const digest = await hmacSha256Hex(`decoy|${boundedDepth}|${cleanSeed}`, params.secret);
  const n1 = uint32FromHex(digest, 0);
  const n2 = uint32FromHex(digest, 4);

  const collection = COLLECTIONS[n1 % COLLECTIONS.length] ?? COLLECTIONS[0]!;
  const entryCode = `${digest.slice(0, 4).toUpperCase()}-${String((n2 % 9000) + 1000).padStart(4, '0')}`;
  const title = `${collection} ${entryCode} (Section ${boundedDepth})`;

  const paragraphs: string[] = [];
  for (let i = 0; i < 3; i++) {
    const subHash = await hmacSha256Hex(`para|${i}|${digest}`, params.secret);
    const subj = SUBJECTS[uint32FromHex(subHash, 0) % SUBJECTS.length] ?? SUBJECTS[0]!;
    const act = ACTIONS[uint32FromHex(subHash, 4) % ACTIONS.length] ?? ACTIONS[0]!;
    const app = APPENDICES[uint32FromHex(subHash, 8) % APPENDICES.length] ?? APPENDICES[0]!;
    const folio = subHash.slice(8, 14).toUpperCase();

    paragraphs.push(
      `Folio ${folio} records ${subj} ${act} for archival sequence ${entryCode}.${i + 1}. ${app}`,
    );
  }

  let childTokens: string[];
  if (params.overrideChildTokens && params.overrideChildTokens.length > 0) {
    childTokens = [...params.overrideChildTokens];
  } else {
    const nextDepth = boundedDepth < boundedMax ? boundedDepth + 1 : 1;
    const count = Math.max(1, Math.min(6, Math.trunc(params.linksPerPage ?? 3)));
    childTokens = [];
    for (let j = 0; j < count; j++) {
      const childHash = await hmacSha256Hex(
        `child|${boundedDepth}|${nextDepth}|${cleanSeed}|${j}`,
        params.secret,
      );
      childTokens.push(await signTrapToken(nextDepth, childHash.slice(0, 12), params.secret));
    }
  }

  const body =
    format === 'plain'
      ? renderDecoyPlain(title, entryCode, paragraphs, childTokens, prefix, basePath, trailingSlash)
      : renderDecoyHtml(title, entryCode, paragraphs, childTokens, prefix, basePath, trailingSlash);

  return {
    status: 200,
    contentType: format === 'plain' ? 'text/plain; charset=utf-8' : 'text/html; charset=utf-8',
    title,
    entryCode,
    depth: boundedDepth,
    seed: cleanSeed,
    childTokens,
    body,
  };
}

function renderDecoyHtml(
  title: string,
  entryCode: string,
  paragraphs: readonly string[],
  childTokens: readonly string[],
  routePrefix: string,
  basePath: string,
  trailingSlash: TrailingSlashMode,
): string {
  const lines: string[] = [
    '<!doctype html>',
    '<html lang="en">',
    '<head>',
    '<meta charset="utf-8" />',
    '<meta name="viewport" content="width=device-width, initial-scale=1" />',
    '<meta name="robots" content="noindex, nofollow, noarchive, nosnippet, noai, noimageai" />',
    `<title>${escapeHtml(title)}</title>`,
    '</head>',
    '<body>',
    '<main>',
    `<article data-entry="${escapeHtml(entryCode)}">`,
    `<h1>${escapeHtml(title)}</h1>`,
  ];

  for (const p of paragraphs) {
    lines.push(`<p>${escapeHtml(p)}</p>`);
  }

  lines.push('<nav aria-label="Cross-References">', '<ul>');
  childTokens.forEach((token, idx) => {
    const href = formatTrapPath(basePath, routePrefix, token, trailingSlash);
    const label = `Cross-Reference Entry ${idx + 1} (${token.slice(0, 14)})`;
    lines.push(`<li><a href="${escapeHtml(href)}" rel="nofollow noopener">${escapeHtml(label)}</a></li>`);
  });
  lines.push('</ul>', '</nav>', '</article>', '</main>', '</body>', '</html>');

  return `${lines.join('\n')}\n`;
}

function renderDecoyPlain(
  title: string,
  entryCode: string,
  paragraphs: readonly string[],
  childTokens: readonly string[],
  routePrefix: string,
  basePath: string,
  trailingSlash: TrailingSlashMode,
): string {
  const suffix = trailingSlash === 'never' ? '' : '/';
  const lines: string[] = [
    title,
    '='.repeat(Math.min(72, title.length)),
    `Reference: ${entryCode}`,
    '',
  ];
  for (const p of paragraphs) {
    lines.push(p, '');
  }
  lines.push('Cross-References:');
  for (const token of childTokens) {
    lines.push(`- ${basePath}/${routePrefix}/${token}${suffix}`);
  }
  return `${lines.join('\n')}\n`;
}
