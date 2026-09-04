import type { APIRoute } from 'astro';
import { getCollection } from 'astro:content';

export const prerender = true;

const CORS_HEADERS = {
  'Content-Type': 'application/json',
  'Access-Control-Allow-Origin': '*',
  'Cache-Control': 'public, max-age=300',
};

// Splits the markdown body into { summary, whatWasObserved, mitigation }
// based on the site's fixed "## Summary / ## What was observed / ## Mitigation"
// template. Falls back gracefully if a section is missing.
function splitSections(body: string) {
  const headingRegex = /^## (.+)$/gm;
  const matches = [...body.matchAll(headingRegex)];
  const sections: Record<string, string> = {};

  for (let i = 0; i < matches.length; i++) {
    const heading = matches[i][1].trim().toLowerCase();
    const start = matches[i].index! + matches[i][0].length;
    const end = i + 1 < matches.length ? matches[i + 1].index! : body.length;
    sections[heading] = body.slice(start, end).trim();
  }

  return {
    summary: sections['summary'] ?? null,
    whatWasObserved: sections['what was observed'] ?? null,
    mitigation: sections['mitigation'] ?? null,
  };
}

export async function getStaticPaths() {
  const cases = await getCollection('cases');
  return cases.map((c) => ({
    params: { caseId: c.data.caseId },
    props: { entry: c },
  }));
}

export const GET: APIRoute = async ({ props }) => {
  const entry = (props as any).entry;
  const d = entry.data;
  const sections = splitSections(entry.body);

  const payload = {
    caseId: d.caseId,
    title: d.title,
    url: `https://ragbleed.com/case/${entry.slug}`,
    filed: d.filed,
    filedDisplay: d.filedDisplay,
    firstObserved: d.firstObserved,
    severity: d.severity,
    category: d.category,
    status: d.status,
    affectedSystems: d.affectedSystems,
    cve: d.cve ?? null,
    readTime: d.readTime,
    related: d.related,
    content: sections,
  };

  return new Response(JSON.stringify(payload, null, 2), { headers: CORS_HEADERS });
};
