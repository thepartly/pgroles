# Research: Documentation search

Status: implemented with Pagefind 1.5.2
Date: 2026-09-21

## Recommendation

Use Pagefind for the first search implementation. The static-site relevance evaluation below supports this choice. Keep one index across Docs and Learn PostgreSQL, show Guide / Reference / Course labels, and offer optional filters. Never infer a destination filter from the page where search was opened.

Pagefind is now part of `npm run build`. The browser UI searches the built index and loads result details on demand. Search stays global unless the reader explicitly selects a filter.

## Fit with this repository

The site uses Next.js with Markdoc and static export (`docs/package.json`, `docs/next.config.js`). `docs/src/components/Layout.jsx` provides an article boundary; `docs/src/lib/navigation.mjs` centralizes destination information. `docs/src/components/Search.jsx` implements the search dialog. The Pages workflow publishes `docs/out`, including previews under a configurable `DOCS_BASE_PATH` (`.github/workflows/docs-pages.yml`).

Pagefind indexes generated HTML and ships a browser search bundle without a search server. That fits the existing deployment: run a pinned Pagefind dependency after the static export, then publish its generated assets with the same build. The index and pages can therefore advance together. [Pagefind getting started](https://pagefind.app/docs/)

## Alternatives considered

| Option | Capabilities supported by primary sources | Assessment for pgroles |
| --- | --- | --- |
| Pagefind | Static HTML indexing, browser API, excerpts and anchored sub-results; filters and metadata. [API](https://pagefind.app/docs/api/), [filters](https://pagefind.app/docs/filtering/) | Best initial fit: preserves static hosting and avoids owning a content extraction pipeline. Measured query quality is recorded below. |
| Algolia DocSearch | Crawler selectors can extract article headings and content, attach custom facet fields and adjust page ranking; React integration is available. [Record extractor](https://docsearch.algolia.com/docs/record-extractor/), [package APIs](https://docsearch.algolia.com/docs/api/) | Strong hosted alternative if service-backed search is acceptable. Adds crawler/index configuration and an external runtime dependency. Revisit if local relevance tuning proves insufficient or hosted search becomes desirable. |
| MiniSearch | In-memory JavaScript full-text engine for browsers and Node, with field boosts, prefix/fuzzy matching, stored fields and result filters. [Repository and API examples](https://github.com/lucaong/minisearch) | Viable for a small corpus and precise application-controlled ranking. We would own extraction, section records, excerpts, highlighting, serialization/loading and the UI. More custom work than Pagefind for this site. |

These are implementation tradeoffs, not latency or price comparisons. DocSearch eligibility, service terms and package compatibility should be checked if that option is selected; no free-service assumption is needed for this recommendation.

## Indexing and results contract

Mark the article, including its title, with `data-pagefind-body`. Explicitly exclude the mobile contents disclosure, interactive lab/editor controls and other article-local navigation with `data-pagefind-ignore`. Include rendered reference tables and code examples: command flags and field identifiers are essential search content. Once any page uses the body marker, pages without it are omitted, so deliberately mark every intended documentation/course layout and exclude interactive Explorer state. [Pagefind indexing](https://pagefind.app/docs/indexing/)

Derive `destination` and `content_type` from the shared page metadata. Use separate values such as Docs / Learn PostgreSQL and Guide / Reference / Course; destination alone cannot distinguish a guide from a reference. Export both result metadata for badges and filter values for optional narrowing. Include the title in result metadata; the build identifier remains in the page footer. [Pagefind metadata](https://pagefind.app/docs/metadata/), [filter attributes](https://pagefind.app/docs/filtering/)

Use the Pagefind JavaScript API in the existing search component to render title, content-type badge, excerpt and relevant heading link. Its results provide metadata and sub-results, and filters are explicit arguments. Initialize on the first query; load only displayed result details. Respect the deployment base path when importing the generated bundle, and test preview links as well as root-hosted links. [Pagefind API](https://pagefind.app/docs/api/)

## Relevance acceptance contract

The browser suite checks these against the real generated index. Expected pages must appear in the top three, with the RLS limitation in the top five. The observed order is shown below:

| Query | Observed leading results | Assessment |
| --- | --- | --- |
| `exclusive` | Memberships; Manifest reference; Limitations | Both requested pages are near the top; the guide precedes the field reference. The reference links to `#exclusive`. |
| `approval pending` | Ephemeral access; Plan approval; Operator troubleshooting | Both requested operator guides appear in the top three, behind the ephemeral-access guide. |
| `review-out` | Recorded reviews; CLI reference; CI/CD | Requested order; `--review-out` returns the same ordering. |
| `RLS` | Row-level-security lesson; limitations; playground; course overview; alternatives | Course is first and the product boundary remains visible with a Reference badge. |
| `permission denied` | Executor privileges; Operator troubleshooting; Operator status | The two requested operational pages lead. |

The implementation keeps default ranking. Precise visible headings improved the field-reference and troubleshooting results. Experiments with global heading weights of 8, 16 and 32 did not move the first two queries into the preferred order; larger weights also moved the RLS limitation ahead of the course. Adjusting document-length and term-frequency ranking likewise failed to improve the full query set. Those changes were rejected. There are no hard-coded query redirects or destination boosts.

The two remaining ordering differences are explicit follow-up opportunities, not claims of exact ranking parity. The suite also tests identical results when opened from a course, optional filters, empty results, pagination, rapid query changes, keyboard selection and focus restoration at 320px, preview-safe anchored URLs, and recovery after module or fragment download failures. Boilerplate and interactive controls are excluded from the index. Typo tolerance is not an acceptance guarantee.

Start with default ranking. Pagefind boosts headings and supports region weights; its ranking settings also control document-length and term-frequency effects. Adjust only after recording the failing query and inspecting its result excerpts. Avoid a blanket Reference-over-Course boost: it would work against the RLS goal. Prefer precise headings, useful introductory descriptions and selective field/flag emphasis, then rerun the whole corpus of queries. [Content weighting](https://pagefind.app/docs/weighting/), [ranking controls](https://pagefind.app/docs/ranking/)

Default punctuation normalization needs deliberate testing for `review-out` and `--review-out`; Pagefind documents an option to retain selected characters. Do not change tokenization globally before measuring the effect on command and prose queries. Spell out “row-level security (RLS)” in relevant indexed content so the acronym has an explicit match. [Special-character indexing](https://pagefind.app/docs/indexing/)

## Implementation and follow-up

The build indexes 56 article pages and exports two filters. It fails if indexing fails. The browser imports the generated bundle relative to the deployment base path; both root and preview deployments are tested. Explorer state is not indexed.

Keep the five-query browser checks as a relevance regression suite. Add real reader queries before tuning further. Revisit section-level indexing or a hosted engine only if that broader corpus demonstrates a gap that content structure and Pagefind cannot address. The current implementation needs no search service, credentials or crawler schedule.

A cold local Chromium query for `exclusive` took 302 ms from input to rendered results (including the 150 ms debounce) and transferred 87,410 bytes of Pagefind resources. This is a localhost baseline with a fresh browser context, not a production or throttled-mobile latency claim. Re-measure on the deployed site before setting a latency budget.
