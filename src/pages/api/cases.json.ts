import type { APIRoute } from 'astro';
import { getCollection } from 'astro:content';

export const prerender = true;

const CORS_HEADERS = {
  'Content-Type': 'application/json',
  'Access-Control-Allow-Origin': '*',
  'Cache-Control': 'public, max-age=300',
};

export const GET: APIRoute = async () => {
  const cases = await getCollection('cases');

  const sorted = cases.sort((a, b) => b.data.filed.localeCompare(a.data.filed));

  const payload = sorted.map((c) => ({
    caseId: c.data.caseId,
    title: c.data.title,
    url: `https://ragbleed.com/case/${c.slug}`,
    filed: c.data.filed,
    filedDisplay: c.data.filedDisplay,
    firstObserved: c.data.firstObserved,
    severity: c.data.severity,
    category: c.data.category,
    status: c.data.status,
    affectedSystems: c.data.affectedSystems,
    cve: c.data.cve ?? null,
    readTime: c.data.readTime,
    related: c.data.related,
  }));

  return new Response(
    JSON.stringify({ count: payload.length, cases: payload }, null, 2),
    { headers: CORS_HEADERS }
  );
};
