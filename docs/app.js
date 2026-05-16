/* global location, fetch, document, window, jsyaml, navigator */
/* Open SSPM — Specification Document
 * ----------------------------------
 * Renders the compiled descriptor and metaschemas as a structured spec
 * document. Hash routing, no build step, no framework. The DOM helper
 * `h(...)` is the only abstraction layer; everything else is direct.
 */

const REPO_URL = "https://github.com/open-sspm/open-sspm-spec";
const SCHEMA_FILES = {
  "opensspm.ruleset": "opensspm.ruleset.schema.yaml",
  "opensspm.profile": "opensspm.profile.schema.yaml",
  "opensspm.test_case": "opensspm.test_case.schema.yaml",
  "opensspm.entity_policy_pack": "opensspm.entity_policy_pack.schema.yaml",
};
const SCHEMA_BLURBS = {
  "opensspm.ruleset": "A ruleset is a connector-scoped set of rules. Automated checks use Rego modules and queries, plus severity, monitoring status, and the dataset(s) each rule depends on.",
  "opensspm.profile": "A profile bundles versioned rulesets into a baseline (for example, a CIS or DoD STIG benchmark).",
  "opensspm.test_case": "A test case provides fixture data and an expected verdict against a rule or entity policy pack, used by the verifier to exercise Rego semantics.",
  "opensspm.entity_policy_pack": "An entity policy pack evaluates one entity at a time and produces risk levels, scores, suggestions, and signals.",
};

const state = {
  descriptor: null,
  schemas: {},
  query: "",
  facets: { severity: new Set(), monitoring: new Set(), engine: new Set() },
};

/* ---------------------------- DOM helpers ----------------------------- */

function h(tag, attrs, ...children) {
  const node = document.createElement(tag);
  if (attrs && typeof attrs === "object" && !(attrs instanceof Node) && !Array.isArray(attrs)) {
    for (const [k, v] of Object.entries(attrs)) {
      if (v == null || v === false) continue;
      if (k === "class") node.className = v;
      /* No "html" shortcut: it would bypass escaping. Use node.innerHTML
         directly at the call site where escapeHtml has been applied. */
      else if (k === "text") node.textContent = String(v);
      else if (k === "dataset") for (const [dk, dv] of Object.entries(v)) node.dataset[dk] = String(dv);
      else if (k.startsWith("on") && typeof v === "function") node.addEventListener(k.slice(2).toLowerCase(), v);
      else if (v === true) node.setAttribute(k, "");
      else node.setAttribute(k, String(v));
    }
    appendChildren(node, children);
  } else {
    appendChildren(node, [attrs, ...children]);
  }
  return node;
}
function appendChildren(node, children) {
  for (const c of children.flat(Infinity)) {
    if (c == null || c === false || c === true) continue;
    node.appendChild(typeof c === "string" || typeof c === "number" ? document.createTextNode(String(c)) : c);
  }
}
function $(id) { return document.getElementById(id); }
function escapeHtml(s) {
  return String(s)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}
function setStatus(text, isError = false) {
  const st = $("status");
  if (!st) return;
  st.textContent = text;
  st.dataset.error = isError ? "true" : "false";
  st.hidden = false;
  $("content").hidden = true;
}
function showContent(nodes) {
  const content = $("content");
  content.replaceChildren(...nodes);
  content.hidden = false;
  $("status").hidden = true;
  window.scrollTo({ top: 0, behavior: "instant" in window ? "instant" : "auto" });
}

/* ------------------------------ Routing -------------------------------- */

function parseRoute() {
  const hash = (location.hash || "#overview").replace(/^#/, "");
  const parts = hash.split("/").filter(Boolean).map(decodeURIComponent);
  return { view: parts[0] || "overview", rest: parts.slice(1) };
}

/* ------------------------------ YAML output --------------------------- */

function dumpYAML(v) {
  if (v === undefined) return "";
  const dumped = jsyaml.dump(v, { noRefs: true, lineWidth: 100, sortKeys: false, quotingType: '"', forceQuotes: false });
  return dumped.endsWith("\n") ? dumped.slice(0, -1) : dumped;
}

/* Small YAML highlighter for js-yaml output. Token classes match style.css. */
function highlightYAML(yaml) {
  const lines = yaml.split("\n");
  return lines.map(highlightYAMLLine).join("\n");
}
function highlightYAMLLine(line) {
  if (line === "") return "";
  const m = line.match(/^(\s*)(.*)$/);
  const indent = m[1];
  let rest = m[2];
  if (rest === "") return line;
  if (rest.startsWith("#")) return indent + `<span class="tok-comment">${escapeHtml(rest)}</span>`;
  if (rest === "---" || rest === "...") return indent + `<span class="tok-doc">${escapeHtml(rest)}</span>`;

  let listMark = "";
  if (rest === "-") return indent + `<span class="tok-mark">-</span>`;
  if (rest.startsWith("- ")) {
    listMark = `<span class="tok-mark">-</span> `;
    rest = rest.slice(2);
  }
  /* key: value  — key may be quoted or plain */
  const km = rest.match(/^("(?:[^"\\]|\\.)*"|'(?:[^']|'')*'|[^"'#:][^:#]*?)(:)(\s*)(.*)$/);
  if (km) {
    const key = km[1];
    const colon = km[2];
    const sp = km[3];
    const val = km[4];
    return indent + listMark
      + `<span class="tok-key">${escapeHtml(key)}</span>`
      + `<span class="tok-mark">${colon}</span>`
      + sp
      + (val ? highlightYAMLValue(val) : "");
  }
  return indent + listMark + highlightYAMLValue(rest);
}
function highlightYAMLValue(v) {
  if (!v) return "";
  /* Block scalar markers */
  if (/^[|>][+-]?\d?$/.test(v)) return `<span class="tok-mark">${escapeHtml(v)}</span>`;
  /* Inline collections — pass through but escape */
  if (/^\[.*\]$/.test(v) || /^\{.*\}$/.test(v)) return escapeHtml(v);
  /* Quoted strings */
  if (/^"(?:[^"\\]|\\.)*"$/.test(v)) return `<span class="tok-string">${escapeHtml(v)}</span>`;
  if (/^'(?:[^']|'')*'$/.test(v)) return `<span class="tok-string">${escapeHtml(v)}</span>`;
  /* Numbers */
  if (/^-?\d+(\.\d+)?(e[+-]?\d+)?$/i.test(v)) return `<span class="tok-num">${escapeHtml(v)}</span>`;
  /* Booleans / null */
  if (/^(true|false|null|~|yes|no|on|off)$/i.test(v)) return `<span class="tok-bool">${escapeHtml(v)}</span>`;
  /* Anchors / aliases / tags */
  if (/^[&*][^\s]+/.test(v)) return `<span class="tok-anchor">${escapeHtml(v)}</span>`;
  /* Plain scalar — render as string-toned */
  return `<span class="tok-string">${escapeHtml(v)}</span>`;
}

function yamlBlock(value, label) {
  const raw = dumpYAML(value);
  const html = highlightYAML(raw);
  const pre = h("pre", { class: "code" });
  const code = document.createElement("code");
  code.className = "language-yaml";
  code.innerHTML = html;
  pre.appendChild(code);
  const copy = h("button", {
    class: "copy",
    type: "button",
    title: "Copy to clipboard",
    onclick: async () => {
      try {
        await navigator.clipboard.writeText(raw);
        copy.textContent = "copied";
        setTimeout(() => { copy.textContent = label || "copy"; }, 1200);
      } catch { copy.textContent = "—"; }
    },
  }, label || "copy");
  pre.appendChild(copy);
  return pre;
}

/* ------------------------------ Sidebar TOC --------------------------- */

function renderTOC() {
  const d = state.descriptor || {};
  const counts = {
    rulesets: (d.rulesets || []).length,
    profiles: (d.profiles || []).length,
    policyPacks: (d.entity_policy_packs || []).length,
  };
  const toc = $("toc");
  toc.replaceChildren();

  function section(label) {
    const li = h("li", { class: "toc-section" }, label);
    toc.appendChild(li);
  }
  function item(href, label, count, sub = false) {
    const a = h("a", { href }, label, count != null ? h("span", { class: "muted" }, ` (${count})`) : null);
    const li = h("li", { class: "toc-item" + (sub ? " toc-item-sub" : "") }, a);
    toc.appendChild(li);
  }

  section("Front matter");
  item("#overview", "Overview");

  section("Specifications");
  Object.keys(SCHEMA_FILES).forEach((kind) => {
    item(`#schema/${encodeURIComponent(kind)}`, kind, null, true);
  });

  section("Catalog");
  item("#rulesets", "Rulesets", counts.rulesets);
  item("#profiles", "Profiles", counts.profiles);
  item("#policy-packs", "Policy packs", counts.policyPacks);

  section("Indexes");
  item("#requirements", "Requirements");
  item("#artifacts", "Artifacts");

  applyActiveTOC();
}

function applyActiveTOC() {
  const { view } = parseRoute();
  const map = {
    overview: "#overview",
    schemas: "#overview",
    schema: null,
    rulesets: "#rulesets",
    ruleset: "#rulesets",
    rule: "#rulesets",
    profiles: "#profiles",
    profile: "#profiles",
    "policy-packs": "#policy-packs",
    "policy-pack": "#policy-packs",
    requirements: "#requirements",
    artifacts: "#artifacts",
    search: "#overview",
  };
  const target = map[view];
  document.querySelectorAll(".toc a").forEach((a) => {
    const href = a.getAttribute("href") || "";
    let active = href === target;
    if (view === "schema") {
      const kind = parseRoute().rest[0] || "";
      active = href === `#schema/${encodeURIComponent(kind)}`;
    }
    a.classList.toggle("active", active);
    if (active) a.setAttribute("aria-current", "page");
    else a.removeAttribute("aria-current");
  });
}


/* ------------------------------ Filtering ----------------------------- */

function matches(q, ...fields) {
  if (!q) return true;
  const qq = q.toLowerCase();
  return fields.some((f) => String(f || "").toLowerCase().includes(qq));
}

/* --------------------------- Schema rendering ------------------------- */

function resolveJsonPointer(doc, ptr) {
  if (!ptr || ptr === "#") return doc;
  if (!ptr.startsWith("#/")) return null;
  const parts = ptr.slice(2).split("/").map((p) => p.replaceAll("~1", "/").replaceAll("~0", "~"));
  let cur = doc;
  for (const p of parts) {
    if (!cur || typeof cur !== "object" || !(p in cur)) return null;
    cur = cur[p];
  }
  return cur;
}
function deref(schema, root, seen = new Set()) {
  if (!schema || typeof schema !== "object") return schema;
  if (!schema.$ref || typeof schema.$ref !== "string") return schema;
  if (seen.has(schema.$ref)) return { ...schema, _circular: true };
  seen.add(schema.$ref);
  const resolved = resolveJsonPointer(root, schema.$ref);
  if (!resolved) return schema;
  return deref(resolved, root, seen);
}
function inferType(schema) {
  if (!schema || typeof schema !== "object") return "unknown";
  if (schema.const !== undefined) return `const`;
  if (Array.isArray(schema.type)) return schema.type.join(" | ");
  if (typeof schema.type === "string") return schema.type;
  if (schema.properties) return "object";
  if (schema.items) return "array";
  if (schema.oneOf) return "oneOf";
  if (schema.anyOf) return "anyOf";
  if (schema.allOf) return "allOf";
  if (schema.enum) return "enum";
  return "any";
}
function schemaDetailLine(schema) {
  if (!schema || typeof schema !== "object") return "";
  const parts = [];
  if (schema.const !== undefined) parts.push(`const = ${JSON.stringify(schema.const)}`);
  if (Array.isArray(schema.enum) && schema.enum.length) {
    const head = schema.enum.slice(0, 6).map((v) => JSON.stringify(v)).join(", ");
    const tail = schema.enum.length > 6 ? `, … (${schema.enum.length - 6} more)` : "";
    parts.push(`enum: ${head}${tail}`);
  }
  if (schema.default !== undefined) parts.push(`default = ${JSON.stringify(schema.default)}`);
  if (schema.format) parts.push(`format = ${schema.format}`);
  if (schema.pattern) parts.push(`pattern = /${schema.pattern}/`);
  if (schema.minimum !== undefined) parts.push(`min = ${schema.minimum}`);
  if (schema.maximum !== undefined) parts.push(`max = ${schema.maximum}`);
  if (schema.minLength !== undefined) parts.push(`minLength = ${schema.minLength}`);
  if (schema.maxLength !== undefined) parts.push(`maxLength = ${schema.maxLength}`);
  if (schema.uniqueItems) parts.push(`unique`);
  if (schema.additionalProperties === false) parts.push(`closed`);
  return parts.join(" · ");
}

function renderSchemaNode(name, schema, root, required, depth, seen) {
  const s = deref(schema, root, new Set(seen));
  const type = inferType(s);
  const desc = (s && typeof s.description === "string") ? s.description : "";
  const detail = schemaDetailLine(s);
  const isObj = type === "object" && s.properties && Object.keys(s.properties).length;
  const isArrOfObj = type === "array" && s.items && (deref(s.items, root, new Set(seen)).type === "object" || deref(s.items, root, new Set(seen)).properties);
  const isUnion = (s.oneOf || s.anyOf || s.allOf);

  const typeLabel = type === "array"
    ? `array<${inferType(deref(s.items || {}, root, new Set(seen)))}>`
    : type;

  const head = h("div", { class: "tree-name" }, name || "(root)");
  const tag = h("div", { class: "tree-type", dataset: { required: required ? "true" : "false" } }, typeLabel);
  const summary = h("summary", {}, head, tag);

  const inner = [];
  if (desc) inner.push(h("div", { class: "tree-desc" }, desc));
  if (detail) inner.push(h("div", { class: "tree-detail" }, detail));

  if (isObj) {
    const childReq = new Set(Array.isArray(s.required) ? s.required : []);
    const names = Object.keys(s.properties).sort();
    const wrap = h("div", { class: "tree-children" }, ...names.map((n) =>
      renderSchemaNode(n, s.properties[n], root, childReq.has(n), depth + 1, seen)
    ));
    inner.push(wrap);
  } else if (isArrOfObj) {
    const item = deref(s.items, root, new Set(seen));
    const wrap = h("div", { class: "tree-children" }, renderSchemaNode("[item]", item, root, false, depth + 1, seen));
    inner.push(wrap);
  } else if (isUnion) {
    const variants = s.oneOf || s.anyOf || s.allOf || [];
    const label = s.oneOf ? "oneOf" : s.anyOf ? "anyOf" : "allOf";
    const wrap = h("div", { class: "tree-children" },
      ...variants.map((v, i) => renderSchemaNode(`${label}[${i}]`, v, root, false, depth + 1, seen))
    );
    inner.push(wrap);
  }

  if (inner.length === 0 || (!isObj && !isArrOfObj && !isUnion)) {
    /* Leaf — render as a flat row instead of details. */
    return h("div", { class: "tree-leaf" }, head, tag,
      desc ? h("div", { class: "tree-desc" }, desc) : null,
      detail ? h("div", { class: "tree-detail" }, detail) : null,
    );
  }
  return h("details", depth <= 1 ? { open: "" } : {}, summary, ...inner);
}

/* ------------------------------ Severity glyph ----------------------- */

function sev(s) {
  const v = String(s || "info").toLowerCase();
  return h("span", { class: "sev", dataset: { sev: v } }, v);
}

/* ----------------------------- Common bits ---------------------------- */

function kicker(text) { return h("div", { class: "kicker" }, text); }
function display(...children) { return h("h1", { class: "display" }, ...children); }
function lede(text) { return h("p", { class: "lede" }, text); }
function dl(rows) {
  return h("dl", { class: "dl" }, ...rows.flatMap(([k, v]) => v == null ? [] : [
    h("dt", {}, k),
    h("dd", {}, v),
  ]));
}
function hash(value) {
  const short = String(value).slice(0, 12);
  return h("span", { class: "hash", title: value }, short, "…");
}
function marg(label, ...children) {
  return h("aside", { class: "marg" },
    label ? h("span", { class: "marg-label" }, label) : null,
    ...children);
}
function section(num, anchor, title) {
  return h("h1", { class: "section", id: anchor },
    num ? h("span", { class: "num" }, `§ ${num}`) : null,
    title);
}

/* ------------------------------ Overview ------------------------------ */

function renderOverview() {
  const d = state.descriptor;
  const v = d.version || {};
  const counts = {
    rulesets: (d.rulesets || []).length,
    profiles: (d.profiles || []).length,
    policyPacks: (d.entity_policy_packs || []).length,
    artifacts: (d.index?.artifacts?.artifacts || []).length,
  };

  const cover = h("section", { class: "cover" },
    kicker(`${v.project || "open-sspm"} / ${v.repo || ""}`),
    display("An open spec for posture and compliance rulesets."),
    lede("YAML-authored rulesets, profiles, and policy packs that any tool can evaluate. Compiled deterministically; canonicalized; SHA-256 addressable."),
    h("div", { class: "cover-meta" },
      h("span", {}, "Spec ", h("strong", {}, v.spec_version || "?")),
      h("span", {}, "Schema ", h("strong", {}, String(v.schema_version ?? "?"))),
      h("span", {}, "Generator ≥ ", h("strong", {}, v.generator_min_version || "?")),
    ),
    h("div", { class: "figures" },
      figure(counts.rulesets, "rulesets", "#rulesets"),
      figure(counts.profiles, "profiles", "#profiles"),
      figure(counts.policyPacks, "policy packs", "#policy-packs"),
      figure(countRules(d), "rules", "#rulesets"),
      figure(counts.artifacts, "artifacts", "#artifacts"),
    ),
  );

  const front = h("div", { class: "card" },
    section(null, "front-matter", "About"),
    h("div", { class: "prose" },
      h("p", {},
        "Open SSPM is a versioned specification — YAML for authoring, JSON Schema for semantics — that describes posture and compliance rulesets, the profiles that bundle them, and the entity policy packs that score risk."
      ),
      h("p", {},
        "This document renders the compiled descriptor produced by ", h("code", {}, "osspec build"),
        ". It is regenerated on every push from the contents of ",
        h("code", {}, "specs/"), " into ",
        h("code", {}, "docs/descriptor.v2.yaml"), " and the metaschemas under ",
        h("code", {}, "docs/metaschema/"), "."
      ),
      h("p", {},
        "Hard boundary: this repo defines ", h("strong", {}, "no"),
        " connectors and no dataset contracts. Datasets referenced by checks are external inputs, supplied at evaluation time."
      ),
    ),
  );

  const orient = h("div", { class: "card" },
    section(null, "orientation", "Authoring shapes"),
    h("dl", { class: "dl" },
      h("dt", {}, "Ruleset policy"), h("dd", {}, "Shared Rego modules can live under ", h("code", {}, "ruleset.policy"), " and be reused by automated rule checks."),
      h("dt", {}, "Rule checks"), h("dd", {}, h("code", {}, "check.engine: rego"), " with ", h("code", {}, "check.query"), " selecting the result object for the rule."),
      h("dt", {}, "Evaluation"), h("dd", {}, "Rule Rego receives ", h("code", {}, "input.datasets"), ", ", h("code", {}, "input.params"), " and ", h("code", {}, "input.rule"), " and returns a verdict object."),
    ),
  );

  const tocDoc = h("ol", { class: "toc-doc" },
    tocLink("#schema/opensspm.ruleset", "Ruleset schema", "Connector-scoped, hash-addressable"),
    tocLink("#schema/opensspm.profile", "Profile schema", "Bundles of rulesets"),
    tocLink("#schema/opensspm.test_case", "Test-case schema", "Fixtures for verifying checks"),
    tocLink("#schema/opensspm.entity_policy_pack", "Policy-pack schema", "Per-entity risk evaluation"),
    tocLink("#rulesets", "Rulesets", `${counts.rulesets} compiled, ${countRules(d)} rules total`),
    tocLink("#profiles", "Profiles", `${counts.profiles} bundles`),
    tocLink("#policy-packs", "Entity policy packs", `${counts.policyPacks} packs`),
    tocLink("#requirements", "Requirements index", "Datasets, params, engines per ruleset"),
    tocLink("#artifacts", "Artifacts index", `${counts.artifacts} entries`),
  );

  const contents = h("div", { class: "card" },
    section(null, "contents", "Contents"),
    tocDoc,
  );

  return [cover, front, orient, contents];
}

function figure(num, label, href) {
  return h("div", { class: "figure" },
    h("div", { class: "figure-num" }, String(num)),
    h("div", { class: "figure-label" }, h("a", { href }, label)),
  );
}
function tocLink(href, title, sub) {
  return h("li", {}, h("a", { href }, title), h("span", { class: "toc-doc-meta" }, sub || ""));
}
function countRules(d) {
  let n = 0;
  for (const c of d.rulesets || []) n += (c.object?.ruleset?.rules || []).length;
  return n;
}

/* ------------------------------ Schemas ------------------------------- */

function renderSchemaDoc(kind) {
  const schema = state.schemas[kind];
  if (!schema) {
    return [
      h("div", { class: "card" },
        kicker("Schema"),
        display(h("em", {}, kind || "unknown")),
        lede("This metaschema isn't loaded. Re-run osspec build and reload."),
      ),
    ];
  }
  const blurb = SCHEMA_BLURBS[kind] || schema.description || "";
  const required = new Set(Array.isArray(schema.required) ? schema.required : []);
  const props = schema.properties && typeof schema.properties === "object"
    ? Object.keys(schema.properties).sort()
    : [];

  const tree = h("div", { class: "tree" },
    ...props.map((p) => renderSchemaNode(p, schema.properties[p], schema, required.has(p), 0, new Set())),
  );

  const example = exampleForKind(kind);
  const docPath = `docs/metaschema/${SCHEMA_FILES[kind] || ""}`;

  const cover = h("section", { class: "card" },
    kicker(`Schema — ${kind}`),
    display(serifTitle(schema.title || kind)),
    lede(blurb),
    dl([
      ["$id", h("code", {}, schema.$id || "—")],
      ["$schema", h("code", {}, schema.$schema || "—")],
      ["closed", schema.additionalProperties === false ? "yes (additionalProperties = false)" : "no"],
      ["source", h("code", {}, docPath)],
    ]),
  );

  const fields = h("section", { class: "card" },
    section(null, "fields", "Fields"),
    h("p", { class: "muted" }, "Click a node to expand. ✱ marks required; ", h("code", {}, "closed"), " means additional properties are rejected."),
    tree,
  );

  const ex = example ? h("section", { class: "card" },
    section(null, "example", "Example"),
    h("p", { class: "muted" }, "Drawn from the first compiled object of this kind."),
    yamlBlock(example, "copy yaml"),
  ) : null;

  const raw = h("section", { class: "card" },
    section(null, "schema-yaml", "Source"),
    h("p", { class: "muted" }, "The metaschema as authored, verbatim."),
    h("details", {},
      h("summary", { style: "cursor: pointer; font-family: var(--mono); font-size: 12px; letter-spacing: 0.06em; text-transform: uppercase; color: var(--ink-3); padding: 8px 0;" }, "show / hide source"),
      yamlBlock(schema, "copy yaml"),
    ),
  );

  return [cover, fields, ex, raw].filter(Boolean);
}

function exampleForKind(kind) {
  const d = state.descriptor;
  switch (kind) {
    case "opensspm.ruleset": return d.rulesets?.[0]?.object || null;
    case "opensspm.profile": return d.profiles?.[0]?.object || null;
    case "opensspm.entity_policy_pack": return d.entity_policy_packs?.[0]?.object || null;
    default: return null;
  }
}

function serifTitle(text) {
  return h("span", {}, String(text));
}

/* ------------------------------ Rulesets ------------------------------ */

function rulesetFacets(d) {
  const sevs = new Map();
  const mons = new Map();
  const engs = new Map();
  for (const c of d.rulesets || []) {
    for (const r of c.object?.ruleset?.rules || []) {
      const s = r.severity || "info";
      sevs.set(s, (sevs.get(s) || 0) + 1);
      const m = r.monitoring?.status || "—";
      mons.set(m, (mons.get(m) || 0) + 1);
      const e = r.check?.engine || "—";
      engs.set(e, (engs.get(e) || 0) + 1);
    }
  }
  return { sevs, mons, engs };
}

function facetButton(label, count, group, value) {
  const pressed = state.facets[group].has(value);
  const btn = h("button", {
    class: "facet",
    type: "button",
    dataset: group === "severity" ? { sev: value } : {},
    "aria-pressed": pressed ? "true" : "false",
    onclick: () => {
      if (state.facets[group].has(value)) state.facets[group].delete(value);
      else state.facets[group].add(value);
      render();
    },
  }, label, count != null ? h("span", { class: "facet-count" }, ` ${count}`) : null);
  return btn;
}

function ruleVisible(r) {
  const f = state.facets;
  if (f.severity.size && !f.severity.has(r.severity || "info")) return false;
  if (f.monitoring.size && !f.monitoring.has(r.monitoring?.status || "—")) return false;
  if (f.engine.size && !f.engine.has(r.check?.engine || "—")) return false;
  return matches(state.query, r.key, r.title, r.summary, r.severity, r.monitoring?.status, r.check?.engine);
}

function renderRulesets() {
  const d = state.descriptor;
  const { sevs, mons, engs } = rulesetFacets(d);

  const facetBar = h("div", { class: "facets" },
    h("span", { class: "facets-label" }, "severity"),
    ...["critical", "high", "medium", "low", "info"].map((s) => sevs.has(s) ? facetButton(s, sevs.get(s), "severity", s) : null),
    h("span", { class: "facets-label" }, "monitoring"),
    ...[...mons.entries()].map(([k, v]) => facetButton(k, v, "monitoring", k)),
    h("span", { class: "facets-label" }, "engine"),
    ...[...engs.entries()].map(([k, v]) => facetButton(k, v, "engine", k)),
  );

  const rows = [];
  let ruleTotal = 0;
  let ruleShown = 0;
  for (const c of d.rulesets || []) {
    const rs = c.object.ruleset;
    const total = (rs.rules || []).length;
    const visibleRules = (rs.rules || []).filter(ruleVisible);
    ruleTotal += total;
    ruleShown += visibleRules.length;
    if (state.query && !matches(state.query, rs.key, rs.name) && visibleRules.length === 0) continue;
    rows.push(h("tr", {},
      h("td", {},
        h("a", { href: `#ruleset/${encodeURIComponent(rs.key)}` }, rs.key),
        h("span", { class: "sub" }, rs.name || ""),
      ),
      h("td", {},
        h("code", {}, rs.scope?.kind || "—"),
        rs.scope?.connector_kind ? h("span", { class: "sub" }, h("code", {}, rs.scope.connector_kind)) : null,
      ),
      h("td", { style: "font-variant-numeric: tabular-nums;" }, `${visibleRules.length} / ${total}`),
      h("td", {}, hash(c.hash)),
    ));
  }

  const table = h("table", { class: "ledger" },
    h("thead", {}, h("tr", {},
      h("th", {}, "Ruleset"),
      h("th", {}, "Scope"),
      h("th", { style: "width: 110px" }, "Rules"),
      h("th", { style: "width: 130px" }, "Hash"),
    )),
    h("tbody", {}, ...rows),
  );

  return [
    h("section", { class: "card" },
      kicker("Catalog — rulesets"),
      display("Compiled ", h("span", { class: "upright" }, "rulesets")),
      lede(`${(d.rulesets || []).length} ruleset${((d.rulesets || []).length === 1) ? "" : "s"} containing ${ruleTotal} rules. Filter by severity, monitoring status, or evaluation engine.`),
    ),
    h("section", { class: "card" }, facetBar, table,
      h("p", { class: "muted", style: "font-size: 12px;" },
        `Showing ${ruleShown} of ${ruleTotal} rules across ${rows.length} ruleset${rows.length === 1 ? "" : "s"}.`,
      ),
    ),
  ];
}

function renderRulesetDetail(key) {
  const d = state.descriptor;
  const c = (d.rulesets || []).find((x) => x.object.ruleset.key === key);
  if (!c) {
    return [h("div", { class: "card" },
      kicker("Not found"),
      display("Ruleset ", h("code", {}, key), " is not in this build."),
    )];
  }
  const rs = c.object.ruleset;
  const all = rs.rules || [];
  const visible = all.filter(ruleVisible);
  const { sevs, mons, engs } = (() => {
    const sevs = new Map(), mons = new Map(), engs = new Map();
    for (const r of all) {
      const s = r.severity || "info";
      sevs.set(s, (sevs.get(s) || 0) + 1);
      const m = r.monitoring?.status || "—"; mons.set(m, (mons.get(m) || 0) + 1);
      const e = r.check?.engine || "—"; engs.set(e, (engs.get(e) || 0) + 1);
    }
    return { sevs, mons, engs };
  })();

  const rows = visible.map((r) => h("tr", {},
    h("td", {},
      h("a", { href: `#rule/${encodeURIComponent(rs.key)}/${encodeURIComponent(r.key)}` }, r.key),
      r.summary ? h("span", { class: "sub" }, r.summary) : null,
    ),
    h("td", {}, sev(r.severity || "info")),
    h("td", {}, h("span", { class: "tag tag-monitor", dataset: { status: r.monitoring?.status || "" } }, r.monitoring?.status || "—")),
    h("td", {}, h("span", { class: "tag tag-engine" }, r.check?.engine || "—")),
  ));

  const datasets = (rs.data_contracts || []).map((dc) => h("li", {},
    h("code", {}, `${dc.dataset}@v${dc.version}`),
  ));
  const refs = (rs.references || []).map((r) => h("li", {},
    h("a", { href: r.url || "#", rel: "noopener" }, r.title || r.url),
    r.type ? h("span", { class: "muted" }, ` — ${r.type}`) : null,
  ));

  const facetBar = h("div", { class: "facets" },
    h("span", { class: "facets-label" }, "severity"),
    ...["critical", "high", "medium", "low", "info"].map((s) => sevs.has(s) ? facetButton(s, sevs.get(s), "severity", s) : null),
    h("span", { class: "facets-label" }, "monitoring"),
    ...[...mons.entries()].map(([k, v]) => facetButton(k, v, "monitoring", k)),
    h("span", { class: "facets-label" }, "engine"),
    ...[...engs.entries()].map(([k, v]) => facetButton(k, v, "engine", k)),
  );

  return [
    h("section", { class: "card" },
      kicker("Ruleset"),
      display(serifTitle(rs.name || rs.key)),
      h("p", { class: "lede" }, h("code", {}, rs.key)),
      dl([
        ["Source", rs.source?.name ? h("span", {}, rs.source.name, " · ", h("code", {}, rs.source.version || ""), rs.source.date ? h("span", { class: "muted" }, ` · ${rs.source.date}`) : null) : "—"],
        ["Scope", rs.scope?.kind ? h("span", {}, h("code", {}, rs.scope.kind), rs.scope.connector_kind ? h("span", {}, " · ", h("code", {}, rs.scope.connector_kind)) : null) : "—"],
        ["Path", h("code", {}, c.source_path)],
        ["Hash", hash(c.hash)],
        ["Rules", `${all.length} (showing ${visible.length})`],
      ]),
    ),
    datasets.length ? h("section", { class: "card" },
      section(null, "data-contracts", "Data contracts"),
      h("ul", { style: "list-style: none; padding: 0; margin: 0; columns: 2; column-gap: 28px;" }, ...datasets),
    ) : null,
    refs.length ? h("section", { class: "card" },
      section(null, "references", "References"),
      h("ul", { style: "list-style: none; padding: 0; margin: 0;" }, ...refs),
    ) : null,
    h("section", { class: "card" },
      section(null, "rules", "Rules"),
      facetBar,
      h("table", { class: "ledger" },
        h("thead", {}, h("tr", {},
          h("th", {}, "Key"),
          h("th", { style: "width: 130px" }, "Severity"),
          h("th", { style: "width: 130px" }, "Monitoring"),
          h("th", { style: "width: 110px" }, "Engine"),
        )),
        h("tbody", {}, ...rows),
      ),
    ),
    h("section", { class: "card" },
      section(null, "source", "Source"),
      h("details", {},
        h("summary", { style: "cursor: pointer; font-family: var(--mono); font-size: 12px; letter-spacing: 0.06em; text-transform: uppercase; color: var(--ink-3); padding: 8px 0;" }, "show / hide YAML"),
        yamlBlock(c.object, "copy yaml"),
      ),
    ),
  ].filter(Boolean);
}

function renderRuleDetail(rsKey, ruleKey) {
  const d = state.descriptor;
  const c = (d.rulesets || []).find((x) => x.object.ruleset.key === rsKey);
  if (!c) {
    return [h("div", { class: "card" },
      kicker("Not found"),
      display("Ruleset ", h("code", {}, rsKey), " is not in this build."),
    )];
  }
  const rs = c.object.ruleset;
  const r = (rs.rules || []).find((x) => x.key === ruleKey);
  if (!r) {
    return [h("div", { class: "card" },
      kicker("Not found"),
      display("Rule ", h("code", {}, ruleKey), " is not in ", h("code", {}, rsKey), "."),
    )];
  }

  const required = (r.required_data || []).map((dn) => h("li", {}, h("code", {}, dn)));

  return [
    h("section", { class: "card" },
      kicker(h("a", { href: `#ruleset/${encodeURIComponent(rsKey)}` }, rs.key)),
      display(serifTitle(r.title || r.key)),
      h("p", { class: "lede" }, r.summary || h("em", {}, "(no summary)")),
      h("div", { class: "facets" },
        h("span", { class: "facets-label" }, "severity"), sev(r.severity || "info"),
        h("span", { class: "facets-label" }, "monitoring"),
          h("span", { class: "tag tag-monitor", dataset: { status: r.monitoring?.status || "" } }, r.monitoring?.status || "—"),
        h("span", { class: "facets-label" }, "engine"),
          h("span", { class: "tag tag-engine" }, r.check?.engine || "—"),
      ),
      dl([
        ["Rule key", h("code", {}, r.key)],
        ["Ruleset", h("a", { href: `#ruleset/${encodeURIComponent(rsKey)}` }, rs.key)],
        ["Required data", required.length ? h("ul", { style: "list-style: none; padding: 0; margin: 0;" }, ...required) : "—"],
      ]),
    ),
    r.check ? h("section", { class: "card" },
      section(null, "check", "Check"),
      h("p", { class: "muted" }, "The check definition. Engine ", h("code", {}, r.check.engine || "—"), "."),
      yamlBlock(r.check, "copy yaml"),
    ) : null,
    h("section", { class: "card" },
      section(null, "rule-yaml", "Source"),
      yamlBlock(r, "copy yaml"),
    ),
  ].filter(Boolean);
}

/* ------------------------------ Profiles ----------------------------- */

function renderProfiles() {
  const d = state.descriptor;
  const rows = [];
  for (const c of d.profiles || []) {
    const p = c.object.profile;
    if (!matches(state.query, p.key, p.name, p.description)) continue;
    rows.push(h("tr", {},
      h("td", {},
        h("a", { href: `#profile/${encodeURIComponent(p.key)}` }, p.key),
        h("span", { class: "sub" }, p.name || ""),
      ),
      h("td", { style: "font-variant-numeric: tabular-nums;" }, String((p.rulesets || []).length)),
      h("td", {}, hash(c.hash)),
    ));
  }

  return [
    h("section", { class: "card" },
      kicker("Catalog — profiles"),
      display("Profile ", h("span", { class: "upright" }, "bundles")),
      lede(`Profiles bundle versioned rulesets into baselines (CIS, DoD STIG, etc.). ${rows.length} profile${rows.length === 1 ? "" : "s"}.`),
    ),
    h("section", { class: "card" },
      h("table", { class: "ledger" },
        h("thead", {}, h("tr", {},
          h("th", {}, "Profile"),
          h("th", { style: "width: 110px" }, "Rulesets"),
          h("th", { style: "width: 130px" }, "Hash"),
        )),
        h("tbody", {}, ...rows),
      ),
    ),
  ];
}

function renderProfileDetail(key) {
  const d = state.descriptor;
  const c = (d.profiles || []).find((x) => x.object.profile.key === key);
  if (!c) {
    return [h("div", { class: "card" },
      kicker("Not found"),
      display("Profile ", h("code", {}, key), " is not in this build."),
    )];
  }
  const p = c.object.profile;
  const rulesetItems = (p.rulesets || []).map((r) => {
    const ref = (d.rulesets || []).find((x) => x.object.ruleset.key === r.key);
    return h("tr", {},
      h("td", {},
        h("a", { href: `#ruleset/${encodeURIComponent(r.key)}` }, r.key),
        ref?.object?.ruleset?.name ? h("span", { class: "sub" }, ref.object.ruleset.name) : null,
      ),
      h("td", {}, h("code", {}, r.version || "—")),
      h("td", { style: "font-variant-numeric: tabular-nums;" }, ref ? String((ref.object.ruleset.rules || []).length) : "—"),
    );
  });

  return [
    h("section", { class: "card" },
      kicker("Profile"),
      display(serifTitle(p.name || p.key)),
      h("p", { class: "lede" }, h("code", {}, p.key)),
      p.description ? h("p", { class: "abstract" }, p.description) : null,
      dl([
        ["Path", h("code", {}, c.source_path)],
        ["Hash", hash(c.hash)],
      ]),
    ),
    h("section", { class: "card" },
      section(null, "rulesets", "Included rulesets"),
      h("table", { class: "ledger" },
        h("thead", {}, h("tr", {},
          h("th", {}, "Ruleset"),
          h("th", { style: "width: 110px" }, "Version"),
          h("th", { style: "width: 90px" }, "Rules"),
        )),
        h("tbody", {}, ...rulesetItems),
      ),
    ),
    h("section", { class: "card" },
      section(null, "profile-yaml", "Source"),
      yamlBlock(c.object, "copy yaml"),
    ),
  ];
}

/* --------------------------- Policy packs ----------------------------- */

function renderPolicyPacks() {
  const d = state.descriptor;
  const rows = [];
  for (const c of d.entity_policy_packs || []) {
    const p = c.object?.entity_policy_pack;
    if (!p) continue;
    if (!matches(state.query, p.metadata?.id, p.metadata?.domain, p.metadata?.version, p.inputs?.schema, p.policy?.package, p.policy?.query)) continue;
    rows.push(h("tr", {},
      h("td", {},
        h("a", { href: `#policy-pack/${encodeURIComponent(p.metadata?.id || "")}` }, p.metadata?.id || "—"),
        p.metadata?.domain ? h("span", { class: "sub" }, p.metadata.domain) : null,
      ),
      h("td", {}, h("code", {}, p.metadata?.version || "—")),
      h("td", {}, h("code", {}, p.inputs?.schema || "—")),
      h("td", {}, h("span", { class: "tag tag-engine" }, p.policy?.engine || "—")),
      h("td", {}, hash(c.hash)),
    ));
  }
  return [
    h("section", { class: "card" },
      kicker("Catalog — policy packs"),
      display("Entity ", h("span", { class: "upright" }, "policy packs")),
      lede("Policy packs evaluate one entity at a time. They produce risk levels, scores, and signals — separate from connector-scoped rulesets."),
    ),
    h("section", { class: "card" },
      h("table", { class: "ledger" },
        h("thead", {}, h("tr", {},
          h("th", {}, "Pack"),
          h("th", { style: "width: 100px" }, "Version"),
          h("th", {}, "Input"),
          h("th", { style: "width: 90px" }, "Engine"),
          h("th", { style: "width: 130px" }, "Hash"),
        )),
        h("tbody", {}, ...rows),
      ),
    ),
  ];
}

function renderPolicyPackDetail(id) {
  const d = state.descriptor;
  const c = (d.entity_policy_packs || []).find((x) => x.object?.entity_policy_pack?.metadata?.id === id);
  if (!c) {
    return [h("div", { class: "card" },
      kicker("Not found"),
      display("Policy pack ", h("code", {}, id), " is not in this build."),
    )];
  }
  const pp = c.object.entity_policy_pack;
  const meta = pp.metadata || {};
  const policy = pp.policy || {};

  return [
    h("section", { class: "card" },
      kicker(`Policy pack — ${meta.domain || ""}`),
      display(serifTitle(meta.id || "—")),
      h("p", { class: "lede" }, "Domain ", h("strong", {}, meta.domain || "?"), " · v", meta.version || "?"),
      dl([
        ["Input schema", h("code", {}, pp.inputs?.schema || "—")],
        ["Engine", h("span", { class: "tag tag-engine" }, policy.engine || "—")],
        ["Package", h("code", {}, policy.package || "—")],
        ["Query", h("code", {}, policy.query || "—")],
        ["Path", h("code", {}, c.source_path)],
        ["Hash", hash(c.hash)],
      ]),
    ),
    h("section", { class: "card" },
      section(null, "policy", "Policy"),
      yamlBlock(policy, "copy yaml"),
    ),
    h("section", { class: "card" },
      section(null, "pack-yaml", "Source"),
      h("details", {},
        h("summary", { style: "cursor: pointer; font-family: var(--mono); font-size: 12px; letter-spacing: 0.06em; text-transform: uppercase; color: var(--ink-3); padding: 8px 0;" }, "show / hide YAML"),
        yamlBlock(c.object, "copy yaml"),
      ),
    ),
  ].filter(Boolean);
}

/* ----------------------------- Indexes -------------------------------- */

function renderRequirements() {
  const d = state.descriptor;
  const rs = d.index?.requirements?.rulesets || [];
  const packs = d.index?.requirements?.entity_policy_packs || [];
  const filteredRS = rs.filter((x) => matches(state.query, x.ruleset_key, x.scope?.kind, x.scope?.connector_kind, ...(x.engines || []), ...(x.datasets_referenced || [])));

  return [
    h("section", { class: "card" },
      kicker("Index — requirements"),
      display("Requirements ", h("span", { class: "upright" }, "Index")),
      lede("Computed requirements per ruleset (engines, datasets, inputs) and per policy pack (input schemas and Rego metadata)."),
    ),
    h("section", { class: "card" },
      section(null, "requirements-rulesets", "Per ruleset"),
      h("table", { class: "ledger" },
        h("thead", {}, h("tr", {},
          h("th", {}, "Ruleset"),
          h("th", {}, "Scope"),
          h("th", {}, "Engines"),
          h("th", {}, "Datasets"),
          h("th", {}, "Inputs"),
        )),
        h("tbody", {}, ...filteredRS.map((rr) => h("tr", {},
          h("td", {}, h("a", { href: `#ruleset/${encodeURIComponent(rr.ruleset_key)}` }, rr.ruleset_key)),
          h("td", {},
            h("code", {}, rr.scope?.kind || "—"),
            rr.scope?.connector_kind ? h("span", { class: "sub" }, h("code", {}, rr.scope.connector_kind)) : null,
          ),
          h("td", {}, ...(rr.engines || []).flatMap((e, i) => [i ? " · " : "", h("code", {}, e)])),
          h("td", {}, (rr.datasets || []).length
            ? h("span", {}, ...(rr.datasets || []).flatMap((ds, i) => [
                i ? h("span", { class: "muted" }, " · ") : "",
                h("code", {}, `${ds.dataset}@v${ds.version}`),
              ]))
            : h("span", { class: "muted" }, "—")),
          h("td", {}, (rr.inputs || []).length
            ? h("span", {}, ...(rr.inputs || []).flatMap((input, i) => [
                i ? h("span", { class: "muted" }, " · ") : "",
                h("code", {}, input.type ? `${input.name}:${input.type}` : input.name),
              ]))
            : h("span", { class: "muted" }, "—")),
        ))),
      ),
    ),
    packs.length ? h("section", { class: "card" },
      section(null, "requirements-packs", "Per policy pack"),
      h("table", { class: "ledger" },
        h("thead", {}, h("tr", {},
          h("th", {}, "Pack"),
          h("th", {}, "Domain"),
          h("th", {}, "Input"),
          h("th", {}, "Rego"),
        )),
        h("tbody", {}, ...packs.map((p) => h("tr", {},
          h("td", {}, h("a", { href: `#policy-pack/${encodeURIComponent(p.policy_pack_id)}` }, p.policy_pack_id)),
          h("td", {}, h("code", {}, p.domain || "—")),
          h("td", {}, h("code", {}, p.input_schema || "—")),
          h("td", { style: "max-width: 420px;" },
            h("code", {}, p.rego_package || "—"),
            p.rego_query ? h("span", { class: "sub" }, h("code", {}, p.rego_query)) : null,
            p.rego_sha256 ? h("span", { class: "sub" }, hash(p.rego_sha256)) : null,
          ),
        ))),
      ),
    ) : null,
  ].filter(Boolean);
}

function renderArtifacts() {
  const d = state.descriptor;
  const a = d.index?.artifacts?.artifacts || [];
  const rows = a.filter((x) => matches(state.query, x.kind, x.key, x.source_path, x.hash));
  return [
    h("section", { class: "card" },
      kicker("Index — artifacts"),
      display("Artifacts ", h("span", { class: "upright" }, "Index")),
      lede(`${a.length} artifacts. Every compiled object is content-addressed by SHA-256.`),
    ),
    h("section", { class: "card" },
      h("table", { class: "ledger compact" },
        h("thead", {}, h("tr", {},
          h("th", {}, "Kind"),
          h("th", {}, "Key"),
          h("th", {}, "Source"),
          h("th", {}, "Hash"),
        )),
        h("tbody", {}, ...rows.map((r) => h("tr", {},
          h("td", {}, h("code", {}, r.kind)),
          h("td", {}, h("code", {}, r.key)),
          h("td", {}, h("code", {}, r.source_path)),
          h("td", {}, hash(r.hash)),
        ))),
      ),
    ),
  ];
}

/* ----------------------------- Search --------------------------------- */

function buildSearchIndex() {
  const idx = [];
  const d = state.descriptor;
  for (const c of d.rulesets || []) {
    const rs = c.object.ruleset;
    idx.push({ kind: "ruleset", key: rs.key, label: rs.name || rs.key, sub: rs.scope?.connector_kind || rs.scope?.kind || "", href: `#ruleset/${encodeURIComponent(rs.key)}`, hay: [rs.key, rs.name, rs.scope?.kind, rs.scope?.connector_kind].join(" ") });
    for (const r of rs.rules || []) {
      idx.push({ kind: "rule", key: r.key, label: r.title || r.key, sub: `${rs.key} · ${r.severity || ""}`, href: `#rule/${encodeURIComponent(rs.key)}/${encodeURIComponent(r.key)}`, hay: [r.key, r.title, r.summary, r.severity, r.check?.engine].join(" ") });
    }
  }
  for (const c of d.profiles || []) {
    const p = c.object.profile;
    idx.push({ kind: "profile", key: p.key, label: p.name || p.key, sub: p.description || "", href: `#profile/${encodeURIComponent(p.key)}`, hay: [p.key, p.name, p.description].join(" ") });
  }
  for (const c of d.entity_policy_packs || []) {
    const p = c.object?.entity_policy_pack;
    if (!p) continue;
    idx.push({ kind: "policy pack", key: p.metadata?.id || "", label: p.metadata?.id || "", sub: `${p.metadata?.domain || ""} · v${p.metadata?.version || ""}`, href: `#policy-pack/${encodeURIComponent(p.metadata?.id || "")}`, hay: [p.metadata?.id, p.metadata?.domain].join(" ") });
  }
  for (const [kind] of Object.entries(SCHEMA_FILES)) {
    idx.push({ kind: "schema", key: kind, label: kind, sub: SCHEMA_BLURBS[kind] || "", href: `#schema/${encodeURIComponent(kind)}`, hay: kind });
  }
  return idx;
}

function renderSearch() {
  const q = state.query.trim();
  const all = buildSearchIndex();
  const results = q ? all.filter((x) => x.hay.toLowerCase().includes(q.toLowerCase())) : [];

  const grouped = new Map();
  for (const r of results) {
    if (!grouped.has(r.kind)) grouped.set(r.kind, []);
    grouped.get(r.kind).push(r);
  }

  const blocks = [];
  for (const [kind, rs] of grouped) {
    blocks.push(h("section", { class: "card" },
      h("h2", { class: "section" }, `${kind} · ${rs.length}`),
      h("div", { class: "results" },
        ...rs.slice(0, 50).map((r) => h("div", { class: "result" },
          h("span", { class: "result-kind" }, r.kind),
          h("a", { class: "result-title", href: r.href }, r.label,
            r.sub ? h("span", { class: "result-sub" }, r.sub) : null,
          ),
          h("span", { class: "muted", style: "font-family: var(--mono); font-size: 11px;" }, r.key),
        )),
        rs.length > 50 ? h("p", { class: "muted" }, `+${rs.length - 50} more — refine the query.`) : null,
      ),
    ));
  }

  return [
    h("section", { class: "card" },
      kicker("Search"),
      display(q ? h("span", {}, "Results for ", h("em", {}, q)) : "Search the spec"),
      lede(q ? `${results.length} match${results.length === 1 ? "" : "es"} across rulesets, rules, profiles, policy packs, and schemas.` : "Type a query above to search across rulesets, rules, profiles, policy packs, and schemas. Press / from anywhere to focus the prompt."),
    ),
    ...blocks,
  ];
}

/* ----------------------------- Render switch --------------------------- */

function render() {
  const { view, rest } = parseRoute();
  applyActiveTOC();
  let nodes;
  try {
    if (view === "overview") nodes = renderOverview();
    else if (view === "schemas") nodes = renderOverview();
    else if (view === "schema") nodes = renderSchemaDoc(rest[0] || "");
    else if (view === "rulesets") nodes = renderRulesets();
    else if (view === "ruleset") nodes = renderRulesetDetail(rest[0] || "");
    else if (view === "rule") nodes = renderRuleDetail(rest[0] || "", rest.slice(1).join("/") || "");
    else if (view === "profiles") nodes = renderProfiles();
    else if (view === "profile") nodes = renderProfileDetail(rest[0] || "");
    else if (view === "policy-packs") nodes = renderPolicyPacks();
    else if (view === "policy-pack") nodes = renderPolicyPackDetail(rest[0] || "");
    else if (view === "requirements") nodes = renderRequirements();
    else if (view === "artifacts") nodes = renderArtifacts();
    else if (view === "search") nodes = renderSearch();
    else nodes = [h("div", { class: "card" }, kicker("Not found"), display("Unknown view ", h("em", {}, view)))];
  } catch (e) {
    nodes = [h("div", { class: "card" }, kicker("Render error"), display("Something failed."), h("pre", { class: "code" }, h("code", {}, String(e && e.stack || e)) ))];
  }
  showContent(nodes);
}

/* ------------------------------- Bootstrap ---------------------------- */

async function load() {
  try {
    if (location.protocol === "file:") {
      setStatus(`Open this site over HTTP. Run e.g. python3 -m http.server 8080 in docs/, then visit http://localhost:8080/.`, true);
      return;
    }
    const resp = await fetch("./descriptor.v2.yaml", { cache: "no-store" });
    if (!resp.ok) throw new Error(`descriptor: HTTP ${resp.status}`);
    state.descriptor = jsyaml.load(await resp.text(), { schema: jsyaml.JSON_SCHEMA });

    await Promise.all(Object.entries(SCHEMA_FILES).map(async ([kind, filename]) => {
      const r = await fetch(`./metaschema/${filename}`, { cache: "no-store" });
      if (!r.ok) throw new Error(`schema ${filename}: HTTP ${r.status}`);
      state.schemas[kind] = jsyaml.load(await r.text(), { schema: jsyaml.JSON_SCHEMA });
    }));

    const v = state.descriptor.version || {};
    $("version").textContent = `v${v.spec_version || "?"}${v.schema_version != null ? ` · schema ${v.schema_version}` : ""}`;
    renderTOC();
    render();
  } catch (e) {
    setStatus(`Failed to load specification: ${e.message}`, true);
  }
}

window.addEventListener("hashchange", () => render());
document.addEventListener("DOMContentLoaded", () => {
  const s = $("search");
  s.addEventListener("input", () => {
    state.query = s.value || "";
    render();
  });
  s.addEventListener("keydown", (e) => {
    if (e.key === "Enter") {
      e.preventDefault();
      location.hash = "#search";
    }
    if (e.key === "Escape") {
      s.value = "";
      state.query = "";
      s.blur();
      render();
    }
  });
  document.addEventListener("keydown", (e) => {
    const target = e.target;
    const isEditing = target && (target.tagName === "INPUT" || target.tagName === "TEXTAREA" || target.isContentEditable);
    if (isEditing) return;
    if (e.key === "/" || (e.key === "k" && (e.metaKey || e.ctrlKey))) {
      e.preventDefault();
      s.focus();
      s.select();
    }
  });

  const railToggle = document.querySelector(".rail-toggle");
  const railBody = $("rail-body");
  if (railToggle && railBody) {
    railToggle.addEventListener("click", () => {
      const expanded = railToggle.getAttribute("aria-expanded") === "true";
      railToggle.setAttribute("aria-expanded", expanded ? "false" : "true");
      if (expanded) railBody.setAttribute("hidden", "");
      else railBody.removeAttribute("hidden");
    });
  }

  load();
});
