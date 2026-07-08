# RAGBleed

Vulnerability tracking for RAG systems. Built with Astro.

## Adding a new case file

1. Create `src/content/cases/00X-slug-name.md`
2. Fill in the frontmatter (see existing cases for the schema) — caseId, title, filed, filedDisplay, firstObserved, severity, category, status, affectedSystems, cve, readTime, related
3. Write the body in three sections: `## Summary`, `## What was observed`, `## Mitigation`
4. Commit and push — Vercel rebuilds and deploys automatically

## Local development

```
npm install
npm run dev
```

## Deploy

Connected to Vercel — every push to `main` deploys automatically to production.
