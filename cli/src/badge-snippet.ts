/**
 * `sealmark badge`: copy-paste README snippets (Markdown, HTML, reStructuredText) for a Sealmark badge. Prints, never writes,
 * and never contacts the network: it only builds text from what it is given.
 *
 * Two sources, never mixed:
 * - `--id <id>`: the badge sealmark.dev serves for a server its public fleet grades (https://sealmark.dev/results/<id>/). The
 *   strings are the same ones the site's own copy buttons give (sealmark-site web/lib/badge.mjs, badgeSnippets), so a maintainer
 *   gets one snippet whichever way they ask. The image exists only while the site has a badge for that id; this command cannot
 *   tell, because it does not fetch anything.
 * - `--svg <path or https URL>`: a self-reported badge the maintainer committed (the file `run --format badge` writes). Its alt
 *   text says self-reported, because nothing vouches for a file anyone can edit.
 *
 * Nothing here reads a report or a grade, so it cannot move or claim one.
 */

export const SITE_ORIGIN = "https://sealmark.dev";
export const BADGE_VARIANTS = ["badge", "card", "shields"] as const;
export type BadgeVariant = (typeof BADGE_VARIANTS)[number];

export interface Snippet {
  image: string;
  markdown: string;
  html: string;
  rst: string;
}

export interface BadgeSnippets {
  schema: "sealmark.badge-snippets/1";
  source: "sealmark.dev" | "self-reported";
  /** The page the image links to: the server's results page, or the --link URL. Absent for a self-reported badge without --link. */
  link?: string;
  variants: Partial<Record<BadgeVariant, Snippet>>;
}

/** sealmark.dev server ids: lower-case letters, digits and hyphens (the fleet's ids; the site serves /badge/<id>.svg). */
const ID = /^[a-z0-9](?:[a-z0-9-]{0,98}[a-z0-9])?$/;

/** Throws a plain Error with the message a usage error should print. */
export function checkId(id: string): string {
  const v = id.trim();
  if (/^https?:\/\//i.test(v)) throw new Error(`--id takes the server id, the last part of its results page address (https://sealmark.dev/results/<id>/), not a URL`);
  if (!ID.test(v)) throw new Error(`--id: "${clip(v)}" is not a sealmark.dev server id (lower-case letters, digits and hyphens, as in https://sealmark.dev/results/<id>/)`);
  return v;
}

/**
 * A path or URL that can stand unescaped in Markdown, HTML and reStructuredText: a relative path in the repository, a
 * repository-root path, or an https URL. Spaces, quotes, brackets and backslashes are refused rather than escaped, because each
 * format escapes them differently and a snippet that renders in one and breaks in another is worse than an error.
 */
const SAFE_REF = /^[A-Za-z0-9._~/%?&=+#@!$,;:-]+$/;

export function checkRef(flag: "svg" | "link", ref: string): string {
  const v = ref.trim();
  if (!v) throw new Error(`--${flag} needs a value`);
  if (v.includes("\\")) throw new Error(`--${flag}: use forward slashes (badge/sealmark-report.badge.svg); a README path is a URL path`);
  if (!SAFE_REF.test(v)) throw new Error(`--${flag}: "${clip(v)}" has a space, quote or bracket; use a path or URL without them (or percent-encode them, %20 for a space)`);
  const scheme = /^([A-Za-z][A-Za-z0-9+.-]*):/.exec(v)?.[1]?.toLowerCase();
  if (scheme && scheme !== "https") throw new Error(`--${flag}: only a relative path, a /path from the repository root or an https:// URL works in a README`);
  if (flag === "link" && !scheme) throw new Error("--link takes an https:// URL");
  if (v.startsWith("//")) throw new Error(`--${flag}: write the scheme (https://...)`);
  return v;
}

const clip = (s: string): string => (s.length > 80 ? `${s.slice(0, 79)}…` : s);

function snippet(image: string, alt: string, link?: string): Snippet {
  const img = `![${alt}](${image})`;
  const tag = `<img src="${image}" alt="${alt}">`;
  return {
    image,
    markdown: link ? `[${img}](${link})` : img,
    html: link ? `<a href="${link}">${tag}</a>` : tag,
    rst: [`.. image:: ${image}`, ...(link ? [`   :target: ${link}`] : []), `   :alt: ${alt}`].join("\n"),
  };
}

/** The sealmark.dev badge snippets for one server id, every variant. Same strings as the site's badgeSnippets(id). */
export function siteBadgeSnippets(id: string): BadgeSnippets {
  const v = checkId(id);
  const page = `${SITE_ORIGIN}/results/${v}/`;
  const json = `${SITE_ORIGIN}/badge/${v}.json`;
  const images: Record<BadgeVariant, string> = {
    badge: `${SITE_ORIGIN}/badge/${v}.svg`,
    card: `${SITE_ORIGIN}/badge/${v}-card.svg`,
    shields: `https://img.shields.io/endpoint?url=${encodeURIComponent(json)}`,
  };
  return { schema: "sealmark.badge-snippets/1", source: "sealmark.dev", link: page, variants: Object.fromEntries(BADGE_VARIANTS.map((k) => [k, snippet(images[k], "Sealmark", page)])) };
}

/** Snippets for a self-reported badge the maintainer committed. */
export function selfReportedSnippets(svg: string, link?: string): BadgeSnippets {
  const image = checkRef("svg", svg);
  const target = link === undefined ? undefined : checkRef("link", link);
  return { schema: "sealmark.badge-snippets/1", source: "self-reported", ...(target ? { link: target } : {}), variants: { badge: snippet(image, "Sealmark (self-reported)", target) } };
}

/** The text form: a comment block saying what the image is, then the three formats, each ready to paste as is. */
export function renderBadgeSnippets(s: BadgeSnippets, variant: BadgeVariant = "badge"): string {
  const sn = s.variants[variant];
  if (!sn) throw new Error(`--variant ${variant} is only for a sealmark.dev badge (--id); a self-reported badge is the SVG you committed`);
  const head =
    s.source === "sealmark.dev"
      ? [
          `# Sealmark badge from sealmark.dev (${variant === "badge" ? "flat badge" : variant === "card" ? "card" : "drawn by shields.io"}), linked to ${s.link}`,
          "# It shows the grade from Sealmark's public fleet and appears only while that page lists the server as graded.",
        ]
      : [
          `# Self-reported Sealmark badge: ${sn.image}${s.link ? `, linked to ${s.link}` : ""}`,
          "# Commit the SVG that `sealmark run --format badge` writes, from CI on your main branch, so it tracks the code.",
        ];
  return [...head, "", "Markdown:", sn.markdown, "", "HTML:", sn.html, "", "reStructuredText:", sn.rst, ""].join("\n");
}
