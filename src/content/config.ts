import { defineCollection, z } from 'astro:content';

const cases = defineCollection({
  type: 'content',
  schema: z.object({
    caseId: z.string(),        // "001"
    title: z.string(),
    filed: z.string(),         // "2026-01-02"
    filedDisplay: z.string(),  // "02 Jan 2026"
    firstObserved: z.string(), // "26 Dec 2025"
    severity: z.enum(['low', 'medium', 'high']),
    category: z.string(),
    status: z.string(),
    affectedSystems: z.string(),
    cve: z.string().optional(),
    readTime: z.string().default('5 min read'),
    related: z.array(z.string()).default([]), // array of caseIds, e.g. ["002","004"]
  }),
});

export const collections = { cases };
