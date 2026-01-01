/* global location, fetch, document */

const SCHEMA_FILES = {
  "opensspm.ruleset": "opensspm.ruleset.schema.json",
  "opensspm.dataset_contract": "opensspm.dataset_contract.schema.json",
  "opensspm.connector_manifest": "opensspm.connector_manifest.schema.json",
  "opensspm.profile": "opensspm.profile.schema.json",
  "opensspm.dictionary": "opensspm.dictionary.schema.json",
};

const state = {
  descriptor: null,
  schemas: {},
  query: "",
};

function el(tag, attrs = {}, children = []) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "class") node.className = v;
    else if (k === "text") node.textContent = v;
    else if (k === "html") node.innerHTML = v;
    else node.setAttribute(k, String(v));
  }
  for (const child of children) node.appendChild(child);
  return node;
}

function escapeHtml(s) {
  return String(s)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll("\"", "&quot;")
    .replaceAll("'", "&#039;");
}

function prettyJson(v) {
  return JSON.stringify(v, null, 2);
}

function $(id) {
  return document.getElementById(id);
}

function setStatus(text, isError = false) {
  const st = $("status");
  st.textContent = text;
  st.style.borderColor = isError ? "rgba(255, 107, 107, 0.6)" : "var(--border)";
}

function showContent(nodes) {
  const content = $("content");
  content.replaceChildren(...nodes);
  content.hidden = false;
  $("status").hidden = true;
}

function parseRoute() {
  const hash = (location.hash || "#overview").replace(/^#/, "");
  const parts = hash.split("/").filter(Boolean);
  return { view: parts[0] || "overview", rest: parts.slice(1) };
}

function activeNavHref() {
  const { view, rest } = parseRoute();
  switch (view) {
    case "overview":
      return "#overview";
    case "ruleset":
    case "rulesets":
      return "#rulesets";
    case "dataset":
    case "datasets":
      return "#datasets";
    case "connector":
    case "connectors":
      return "#connectors";
    case "profile":
    case "profiles":
      return "#profiles";
    case "schema":
      return `#schema/${encodeURIComponent(rest[0] || "")}`;
    case "dictionary":
      return "#dictionary";
    case "requirements":
      return "#requirements";
    case "artifacts":
      return "#artifacts";
    default:
      return "";
  }
}

function updateActiveNav() {
  const active = activeNavHref();
  const links = Array.from(document.querySelectorAll("a.navlink"));
  for (const a of links) {
    const href = a.getAttribute("href") || "";
    const isActive = href === active;
    a.classList.toggle("active", isActive);
    if (isActive) a.setAttribute("aria-current", "page");
    else a.removeAttribute("aria-current");
  }
}

function matches(q, ...fields) {
  if (!q) return true;
  const qq = q.toLowerCase();
  return fields.some((f) => String(f || "").toLowerCase().includes(qq));
}

function sevClass(sev) {
  switch (sev) {
    case "critical": return "sev-critical";
    case "high": return "sev-high";
    case "medium": return "sev-medium";
    case "low": return "sev-low";
    default: return "sev-info";
  }
}

function getDescriptor() {
  if (!state.descriptor) throw new Error("descriptor not loaded");
  return state.descriptor;
}

function byRulesetKey() {
  const d = getDescriptor();
  const m = new Map();
  for (const c of d.rulesets || []) m.set(c.object.ruleset.key, c);
  return m;
}

function getSchema(kind) {
  return state.schemas[kind] || null;
}

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
  if (seen.has(schema.$ref)) return schema;
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
  return "unknown";
}

function schemaDetails(schema) {
  if (!schema || typeof schema !== "object") return "";
  const parts = [];
  if (schema.const !== undefined) parts.push(`const=${JSON.stringify(schema.const)}`);
  if (Array.isArray(schema.enum) && schema.enum.length) parts.push(`enum=${schema.enum.map((v) => JSON.stringify(v)).join(", ")}`);
  if (schema.default !== undefined) parts.push(`default=${JSON.stringify(schema.default)}`);
  if (schema.format) parts.push(`format=${schema.format}`);
  if (schema.pattern) parts.push(`pattern=${schema.pattern}`);
  if (schema.minimum !== undefined) parts.push(`min=${schema.minimum}`);
  if (schema.minLength !== undefined) parts.push(`minLength=${schema.minLength}`);
  if (schema.uniqueItems) parts.push(`uniqueItems=true`);
  if (schema.additionalProperties === false) parts.push(`additionalProperties=false`);
  return parts.join(" · ");
}

function flattenSchema(schema, root, path, required, rows, depth, seenRefs) {
  const s = deref(schema, root, seenRefs);
  const type = inferType(s);
  const desc = (s && typeof s.description === "string") ? s.description : "";
  const details = schemaDetails(s);

  rows.push({
    field: path,
    type: type === "array" && s.items ? `array<${inferType(deref(s.items, root, new Set()))}>` : type,
    required,
    description: desc,
    details,
    depth,
  });

  if (type === "object" && s.properties && typeof s.properties === "object") {
    const req = new Set(Array.isArray(s.required) ? s.required : []);
    const names = Object.keys(s.properties).sort();
    for (const name of names) {
      flattenSchema(s.properties[name], root, `${path}.${name}`, req.has(name), rows, depth + 1, new Set(seenRefs || []));
    }
  } else if (type === "array" && s.items) {
    const itemSchema = deref(s.items, root, new Set(seenRefs || []));
    const itemType = inferType(itemSchema);
    if (itemType === "object" && itemSchema.properties) {
      // Provide an explicit item row for readability.
      const itemPath = `${path}[]`;
      const itemDesc = (itemSchema && typeof itemSchema.description === "string") ? itemSchema.description : "Array item.";
      rows.push({
        field: itemPath,
        type: "object",
        required: false,
        description: itemDesc,
        details: schemaDetails(itemSchema),
        depth: depth + 1,
      });
      const req = new Set(Array.isArray(itemSchema.required) ? itemSchema.required : []);
      const names = Object.keys(itemSchema.properties).sort();
      for (const name of names) {
        flattenSchema(itemSchema.properties[name], root, `${itemPath}.${name}`, req.has(name), rows, depth + 2, new Set(seenRefs || []));
      }
    }
  }
}

function renderFieldTable(rows) {
  const filtered = rows.filter((r) => matches(state.query, r.field, r.type, r.description, r.details));
  const table = el("table", { class: "table" }, [
    el("thead", {}, [el("tr", {}, [
      el("th", { text: "Field" }),
      el("th", { text: "Type" }),
      el("th", { text: "Required" }),
      el("th", { text: "Description" }),
      el("th", { text: "Details" }),
    ])]),
    el("tbody", {}, filtered.map((r) => {
      const indent = "&nbsp;".repeat(r.depth * 4);
      return el("tr", {}, [
        el("td", { html: `${indent}<code>${escapeHtml(r.field)}</code>` }),
        el("td", { html: `<code>${escapeHtml(r.type)}</code>` }),
        el("td", { html: r.required ? "<span class=\"chip\">required</span>" : "<span class=\"muted\">optional</span>" }),
        el("td", { html: r.description ? `<span class="muted">${escapeHtml(r.description)}</span>` : "<span class=\"muted\">—</span>" }),
        el("td", { html: r.details ? `<span class="muted">${escapeHtml(r.details)}</span>` : "<span class=\"muted\">—</span>" }),
      ]);
    })),
  ]);
  return table;
}

function exampleForKind(kind) {
  const d = getDescriptor();
  switch (kind) {
    case "opensspm.ruleset":
      return d.rulesets?.[0]?.object || null;
    case "opensspm.dataset_contract":
      return d.dataset_contracts?.[0]?.object || null;
    case "opensspm.connector_manifest":
      return d.connectors?.[0]?.object || null;
    case "opensspm.profile":
      return d.profiles?.[0]?.object || null;
    case "opensspm.dictionary":
      return d.dictionary?.object || null;
    default:
      return null;
  }
}

function renderSchemaDoc(kind) {
  const schema = getSchema(kind);
  if (!schema) {
    return [el("div", { class: "card" }, [
      el("h1", { text: "Schema not loaded" }),
      el("div", { class: "muted", text: `Missing metaschema for ${kind}` }),
    ])];
  }

  const title = schema.title || kind;
  const desc = schema.description || "";
  const required = new Set(Array.isArray(schema.required) ? schema.required : []);
  const props = schema.properties && typeof schema.properties === "object" ? Object.keys(schema.properties).sort() : [];

  const rows = [];
  for (const p of props) {
    flattenSchema(schema.properties[p], schema, p, required.has(p), rows, 0, new Set());
  }

  const example = exampleForKind(kind);

  return [
    el("div", { class: "card" }, [
      el("h1", { html: `Schema: <code>${escapeHtml(kind)}</code>` }),
      el("div", { class: "muted", text: title }),
      desc ? el("div", { class: "muted", text: desc }) : el("div"),
      el("div", { class: "muted", html: `source: <code>docs/metaschema/${escapeHtml(SCHEMA_FILES[kind] || "")}</code>` }),
    ]),
    el("div", { class: "card" }, [
      el("h2", { text: "Fields" }),
      el("div", { class: "muted", text: "Field list is derived from the JSON Schema descriptions." }),
      renderFieldTable(rows),
    ]),
    example ? el("div", { class: "card" }, [
      el("h2", { text: "Example" }),
      el("pre", { class: "json", text: prettyJson(example) }),
    ]) : el("div"),
    el("div", { class: "card" }, [
      el("h2", { text: "JSON Schema" }),
      el("pre", { class: "json", text: prettyJson(schema) }),
    ]),
  ];
}

function renderOverview() {
  const d = getDescriptor();
  const v = d.version || {};
  const counts = {
    rulesets: (d.rulesets || []).length,
    datasets: (d.dataset_contracts || []).length,
    connectors: (d.connectors || []).length,
    profiles: (d.profiles || []).length,
  };

  const cards = [];
  cards.push(el("div", { class: "card" }, [
    el("h1", { text: "Overview" }),
    el("div", { class: "muted", text: `Spec version ${v.spec_version || "?"} (schema_version ${v.schema_version ?? "?"})` }),
    el("div", { class: "chips" }, [
      chip(`rulesets: ${counts.rulesets}`, "#rulesets"),
      chip(`datasets: ${counts.datasets}`, "#datasets"),
      chip(`connectors: ${counts.connectors}`, "#connectors"),
      chip(`profiles: ${counts.profiles}`, "#profiles"),
      chip("requirements", "#requirements"),
      chip("artifacts", "#artifacts"),
    ]),
  ]));

  cards.push(el("div", { class: "card" }, [
    el("h2", { text: "Descriptor" }),
    el("div", { class: "muted", text: "This site renders from the compiled descriptor (no evaluation logic)." }),
    el("pre", { class: "json", text: prettyJson(d) }),
  ]));

  return cards;
}

function chip(label, href) {
  return el("a", { class: "chip", href, text: label });
}

function renderRulesets() {
  const d = getDescriptor();
  const rows = [];
  for (const c of d.rulesets || []) {
    const rs = c.object.ruleset;
    if (!matches(state.query, rs.key, rs.name, rs.scope?.kind, rs.scope?.connector_kind, rs.source?.name, rs.source?.version)) continue;
    rows.push({
      key: rs.key,
      name: rs.name,
      scope: rs.scope?.kind || "",
      connector: rs.scope?.connector_kind || "",
      rules: (rs.rules || []).length,
      hash: c.hash,
    });
  }

  const table = el("table", { class: "table" }, [
    el("thead", {}, [el("tr", {}, [
      el("th", { text: "Ruleset" }),
      el("th", { text: "Scope" }),
      el("th", { text: "Rules" }),
      el("th", { text: "Hash" }),
    ])]),
    el("tbody", {}, rows.map((r) => el("tr", {}, [
      el("td", {}, [el("a", { href: `#ruleset/${encodeURIComponent(r.key)}`, html: `<div><code>${escapeHtml(r.key)}</code></div><div class="muted">${escapeHtml(r.name)}</div>` })]),
      el("td", { html: `<code>${escapeHtml(r.scope)}</code>${r.connector ? `<div class="muted"><code>${escapeHtml(r.connector)}</code></div>` : ""}` }),
      el("td", { text: String(r.rules) }),
      el("td", { html: `<code>${escapeHtml(r.hash)}</code>` }),
    ]))),
  ]);

  return [
    el("div", { class: "card" }, [
      el("h1", { text: "Rulesets" }),
      el("div", { class: "muted", text: "Compiled rulesets (sorted and hashed deterministically)." }),
    ]),
    el("div", { class: "card" }, [table]),
  ];
}

function renderRulesetDetail(key) {
  const d = getDescriptor();
  const m = byRulesetKey();
  const c = m.get(key);
  if (!c) {
    return [el("div", { class: "card" }, [el("h1", { text: "Ruleset not found" }), el("div", { class: "muted", text: key })])];
  }
  const rs = c.object.ruleset;
  const rules = (rs.rules || []).filter((r) => matches(state.query, r.key, r.summary, r.name, r.severity, r.monitoring?.status, r.check?.type));

  const rows = rules.map((r) => el("tr", {}, [
    el("td", { html: `<code>${escapeHtml(r.key)}</code>` }),
    el("td", { html: `<span class="${sevClass(r.severity)}"><code>${escapeHtml(r.severity)}</code></span>` }),
    el("td", { html: `<code>${escapeHtml(r.monitoring?.status || "")}</code>` }),
    el("td", { html: `<code>${escapeHtml(r.check?.type || "")}</code>` }),
    el("td", { html: `<span class="muted">${escapeHtml(r.summary || "")}</span>` }),
  ]));

  const table = el("table", { class: "table" }, [
    el("thead", {}, [el("tr", {}, [
      el("th", { text: "Rule" }),
      el("th", { text: "Severity" }),
      el("th", { text: "Monitoring" }),
      el("th", { text: "Check" }),
      el("th", { text: "Summary" }),
    ])]),
    el("tbody", {}, rows),
  ]);

  return [
    el("div", { class: "card" }, [
      el("h1", { html: `Ruleset: <code>${escapeHtml(rs.key)}</code>` }),
      el("div", { class: "muted", text: rs.name }),
      el("div", { class: "chips" }, [
        chip(`scope: ${rs.scope?.kind || "?"}`, "#rulesets"),
        rs.scope?.connector_kind ? chip(`connector: ${rs.scope.connector_kind}`, "#connectors") : el("span"),
        chip(`rules: ${(rs.rules || []).length}`, "#rulesets"),
      ]),
      el("div", { class: "muted", html: `source: <code>${escapeHtml(rs.source?.name || "")}</code> <code>${escapeHtml(rs.source?.version || "")}</code> <code>${escapeHtml(rs.source?.date || "")}</code>` }),
      el("div", { class: "muted", html: `source_path: <code>${escapeHtml(c.source_path)}</code>` }),
      el("div", { class: "muted", html: `hash: <code>${escapeHtml(c.hash)}</code>` }),
    ]),
    el("div", { class: "card" }, [table]),
    el("div", { class: "card" }, [
      el("h2", { text: "JSON" }),
      el("pre", { class: "json", text: prettyJson(c.object) }),
    ]),
  ];
}

function renderDatasets() {
  const d = getDescriptor();
  const rows = [];
  for (const c of d.dataset_contracts || []) {
    const ds = c.object.dataset;
    const key = `${ds.key}@${ds.version}`;
    if (!matches(state.query, ds.key, ds.description, String(ds.version))) continue;
    rows.push({ key, datasetKey: ds.key, version: ds.version, desc: ds.description || "", hash: c.hash });
  }

  const table = el("table", { class: "table" }, [
    el("thead", {}, [el("tr", {}, [
      el("th", { text: "Dataset" }),
      el("th", { text: "Description" }),
      el("th", { text: "Hash" }),
    ])]),
    el("tbody", {}, rows.map((r) => el("tr", {}, [
      el("td", {}, [el("a", { href: `#dataset/${encodeURIComponent(r.key)}`, html: `<code>${escapeHtml(r.key)}</code>` })]),
      el("td", { html: `<span class="muted">${escapeHtml(r.desc)}</span>` }),
      el("td", { html: `<code>${escapeHtml(r.hash)}</code>` }),
    ]))),
  ]);

  return [
    el("div", { class: "card" }, [
      el("h1", { text: "Dataset Contracts" }),
      el("div", { class: "muted", text: "Contracts define dataset keys, versions, and row schemas." }),
    ]),
    el("div", { class: "card" }, [table]),
  ];
}

function renderDatasetDetail(keyWithVersion) {
  const d = getDescriptor();
  const [k, vStr] = keyWithVersion.split("@");
  const v = Number(vStr);
  const c = (d.dataset_contracts || []).find((x) => x.object.dataset.key === k && x.object.dataset.version === v);
  if (!c) return [el("div", { class: "card" }, [el("h1", { text: "Dataset not found" }), el("div", { class: "muted", text: keyWithVersion })])];
  const ds = c.object.dataset;

  const rowSchema = ds.schema;
  const rows = [];
  if (rowSchema && typeof rowSchema === "object" && rowSchema.properties && typeof rowSchema.properties === "object") {
    const req = new Set(Array.isArray(rowSchema.required) ? rowSchema.required : []);
    const names = Object.keys(rowSchema.properties).sort();
    for (const name of names) {
      flattenSchema(rowSchema.properties[name], rowSchema, name, req.has(name), rows, 0, new Set());
    }
  }

  return [
    el("div", { class: "card" }, [
      el("h1", { html: `Dataset: <code>${escapeHtml(ds.key)}@${escapeHtml(ds.version)}</code>` }),
      ds.description ? el("div", { class: "muted", text: ds.description }) : el("div"),
      el("div", { class: "muted", html: ds.primary_key ? `primary_key: <code>${escapeHtml(ds.primary_key)}</code>` : "" }),
      el("div", { class: "muted", html: ds.recommended_display ? `recommended_display: <code>${escapeHtml(ds.recommended_display)}</code>` : "" }),
      el("div", { class: "muted", html: `source_path: <code>${escapeHtml(c.source_path)}</code>` }),
      el("div", { class: "muted", html: `hash: <code>${escapeHtml(c.hash)}</code>` }),
    ]),
    rows.length ? el("div", { class: "card" }, [
      el("h2", { text: "Fields" }),
      el("div", { class: "muted", text: "Field list is derived from the dataset row JSON Schema." }),
      renderFieldTable(rows),
    ]) : el("div"),
    el("div", { class: "card" }, [
      el("h2", { text: "Row Schema" }),
      el("pre", { class: "json", text: prettyJson(ds.schema) }),
    ]),
    el("div", { class: "card" }, [
      el("h2", { text: "JSON" }),
      el("pre", { class: "json", text: prettyJson(c.object) }),
    ]),
  ];
}

function renderConnectors() {
  const d = getDescriptor();
  const rows = [];
  for (const c of d.connectors || []) {
    const co = c.object.connector;
    if (!matches(state.query, co.kind, co.name)) continue;
    rows.push({ kind: co.kind, name: co.name, provides: (co.provides || []).length, hash: c.hash });
  }
  const table = el("table", { class: "table" }, [
    el("thead", {}, [el("tr", {}, [
      el("th", { text: "Connector" }),
      el("th", { text: "Provides" }),
      el("th", { text: "Hash" }),
    ])]),
    el("tbody", {}, rows.map((r) => el("tr", {}, [
      el("td", {}, [el("a", { href: `#connector/${encodeURIComponent(r.kind)}`, html: `<div><code>${escapeHtml(r.kind)}</code></div><div class="muted">${escapeHtml(r.name)}</div>` })]),
      el("td", { text: String(r.provides) }),
      el("td", { html: `<code>${escapeHtml(r.hash)}</code>` }),
    ]))),
  ]);
  return [
    el("div", { class: "card" }, [el("h1", { text: "Connectors" }), el("div", { class: "muted", text: "Connector manifests declare datasets that a connector can provide." })]),
    el("div", { class: "card" }, [table]),
  ];
}

function renderConnectorDetail(kind) {
  const d = getDescriptor();
  const c = (d.connectors || []).find((x) => x.object.connector.kind === kind);
  if (!c) return [el("div", { class: "card" }, [el("h1", { text: "Connector not found" }), el("div", { class: "muted", text: kind })])];
  const co = c.object.connector;
  const provides = (co.provides || []).map((p) => `<li><code>${escapeHtml(p.dataset)}@${escapeHtml(p.version)}</code></li>`).join("");
  return [
    el("div", { class: "card" }, [
      el("h1", { html: `Connector: <code>${escapeHtml(co.kind)}</code>` }),
      el("div", { class: "muted", text: co.name }),
      el("div", { class: "muted", html: `source_path: <code>${escapeHtml(c.source_path)}</code>` }),
      el("div", { class: "muted", html: `hash: <code>${escapeHtml(c.hash)}</code>` }),
    ]),
    el("div", { class: "card" }, [
      el("h2", { text: "Provides" }),
      el("div", { html: `<ul>${provides || "<li class=\"muted\">(none)</li>"}</ul>` }),
    ]),
    el("div", { class: "card" }, [el("h2", { text: "JSON" }), el("pre", { class: "json", text: prettyJson(c.object) })]),
  ];
}

function renderProfiles() {
  const d = getDescriptor();
  const rows = [];
  for (const c of d.profiles || []) {
    const p = c.object.profile;
    if (!matches(state.query, p.key, p.name, p.description)) continue;
    rows.push({ key: p.key, name: p.name, rulesets: (p.rulesets || []).length, hash: c.hash });
  }
  const table = el("table", { class: "table" }, [
    el("thead", {}, [el("tr", {}, [
      el("th", { text: "Profile" }),
      el("th", { text: "Rulesets" }),
      el("th", { text: "Hash" }),
    ])]),
    el("tbody", {}, rows.map((r) => el("tr", {}, [
      el("td", {}, [el("a", { href: `#profile/${encodeURIComponent(r.key)}`, html: `<div><code>${escapeHtml(r.key)}</code></div><div class="muted">${escapeHtml(r.name)}</div>` })]),
      el("td", { text: String(r.rulesets) }),
      el("td", { html: `<code>${escapeHtml(r.hash)}</code>` }),
    ]))),
  ]);
  return [
    el("div", { class: "card" }, [el("h1", { text: "Profiles" }), el("div", { class: "muted", text: "Profiles bundle rulesets for baselines (e.g., CIS)." })]),
    el("div", { class: "card" }, [table]),
  ];
}

function renderProfileDetail(key) {
  const d = getDescriptor();
  const c = (d.profiles || []).find((x) => x.object.profile.key === key);
  if (!c) return [el("div", { class: "card" }, [el("h1", { text: "Profile not found" }), el("div", { class: "muted", text: key })])];
  const p = c.object.profile;
  const rulesets = (p.rulesets || []).map((r) => {
    const href = `#ruleset/${encodeURIComponent(r.key)}`;
    return `<li><a href="${href}"><code>${escapeHtml(r.key)}</code></a>${r.version ? ` <span class="muted"><code>${escapeHtml(r.version)}</code></span>` : ""}</li>`;
  }).join("");
  return [
    el("div", { class: "card" }, [
      el("h1", { html: `Profile: <code>${escapeHtml(p.key)}</code>` }),
      el("div", { class: "muted", text: p.name }),
      p.description ? el("div", { class: "muted", text: p.description }) : el("div"),
      el("div", { class: "muted", html: `source_path: <code>${escapeHtml(c.source_path)}</code>` }),
      el("div", { class: "muted", html: `hash: <code>${escapeHtml(c.hash)}</code>` }),
    ]),
    el("div", { class: "card" }, [
      el("h2", { text: "Rulesets" }),
      el("div", { html: `<ul>${rulesets || "<li class=\"muted\">(none)</li>"}</ul>` }),
    ]),
    el("div", { class: "card" }, [el("h2", { text: "JSON" }), el("pre", { class: "json", text: prettyJson(c.object) })]),
  ];
}

function renderDictionary() {
  const d = getDescriptor();
  const dict = d.dictionary?.object?.dictionary?.enums || {};
  const names = Object.keys(dict).sort();
  const rows = names.map((n) => {
    const values = (dict[n] || []).map((v) => `<code>${escapeHtml(v)}</code>`).join(", ");
    return el("tr", {}, [el("td", { html: `<code>${escapeHtml(n)}</code>` }), el("td", { html: values })]);
  });
  const table = el("table", { class: "table" }, [
    el("thead", {}, [el("tr", {}, [el("th", { text: "Enum" }), el("th", { text: "Values" })])]),
    el("tbody", {}, rows),
  ]);

  return [
    el("div", { class: "card" }, [el("h1", { text: "Dictionary" }), el("div", { class: "muted", text: "Central enums shared by specs and generated code." })]),
    el("div", { class: "card" }, [table]),
    el("div", { class: "card" }, [el("h2", { text: "JSON" }), el("pre", { class: "json", text: prettyJson(d.dictionary?.object || {}) })]),
  ];
}

function renderArtifacts() {
  const d = getDescriptor();
  const a = d.index?.artifacts?.artifacts || [];
  const rows = a.filter((x) => matches(state.query, x.kind, x.key, x.source_path, x.hash));
  const table = el("table", { class: "table" }, [
    el("thead", {}, [el("tr", {}, [
      el("th", { text: "Kind" }),
      el("th", { text: "Key" }),
      el("th", { text: "Source" }),
      el("th", { text: "Hash" }),
    ])]),
    el("tbody", {}, rows.map((r) => el("tr", {}, [
      el("td", { html: `<code>${escapeHtml(r.kind)}</code>` }),
      el("td", { html: `<code>${escapeHtml(r.key)}</code>` }),
      el("td", { html: `<code>${escapeHtml(r.source_path)}</code>` }),
      el("td", { html: `<code>${escapeHtml(r.hash)}</code>` }),
    ]))),
  ]);
  return [
    el("div", { class: "card" }, [el("h1", { text: "Artifacts Index" }), el("div", { class: "muted", text: "All compiled objects and their stable hashes." })]),
    el("div", { class: "card" }, [table]),
  ];
}

function renderRequirements() {
  const d = getDescriptor();
  const r = d.index?.requirements?.rulesets || [];
  const rows = r.filter((x) => matches(state.query, x.ruleset_key, x.scope?.kind, x.scope?.connector_kind));
  const table = el("table", { class: "table" }, [
    el("thead", {}, [el("tr", {}, [
      el("th", { text: "Ruleset" }),
      el("th", { text: "Scope" }),
      el("th", { text: "Check Types" }),
      el("th", { text: "Datasets" }),
    ])]),
    el("tbody", {}, rows.map((rr) => {
      const ct = (rr.check_types || []).map((x) => `<code>${escapeHtml(x)}</code>`).join(", ");
      const ds = (rr.datasets || []).map((x) => `<code>${escapeHtml(x.dataset)}@${escapeHtml(x.version)}</code>`).join(", ");
      return el("tr", {}, [
        el("td", {}, [el("a", { href: `#ruleset/${encodeURIComponent(rr.ruleset_key)}`, html: `<code>${escapeHtml(rr.ruleset_key)}</code>` })]),
        el("td", { html: `<code>${escapeHtml(rr.scope?.kind || "")}</code>${rr.scope?.connector_kind ? `<div class="muted"><code>${escapeHtml(rr.scope.connector_kind)}</code></div>` : ""}` }),
        el("td", { html: ct || "<span class=\"muted\">(none)</span>" }),
        el("td", { html: ds || "<span class=\"muted\">(none)</span>" }),
      ]);
    })),
  ]);
  return [
    el("div", { class: "card" }, [el("h1", { text: "Requirements Index" }), el("div", { class: "muted", text: "Computed requirements per ruleset (datasets + check types + params)." })]),
    el("div", { class: "card" }, [table]),
  ];
}

function render() {
  updateActiveNav();
  const { view, rest } = parseRoute();

  let nodes = [];
  if (view === "overview") nodes = renderOverview();
  else if (view === "rulesets") nodes = renderRulesets();
  else if (view === "ruleset") nodes = renderRulesetDetail(decodeURIComponent(rest.join("/")));
  else if (view === "datasets") nodes = renderDatasets();
  else if (view === "dataset") nodes = renderDatasetDetail(decodeURIComponent(rest.join("/")));
  else if (view === "connectors") nodes = renderConnectors();
  else if (view === "connector") nodes = renderConnectorDetail(decodeURIComponent(rest.join("/")));
  else if (view === "profiles") nodes = renderProfiles();
  else if (view === "profile") nodes = renderProfileDetail(decodeURIComponent(rest.join("/")));
  else if (view === "dictionary") nodes = renderDictionary();
  else if (view === "artifacts") nodes = renderArtifacts();
  else if (view === "requirements") nodes = renderRequirements();
  else nodes = [el("div", { class: "card" }, [el("h1", { text: "Not found" }), el("div", { class: "muted", text: `Unknown view: ${view}` })])];

  showContent(nodes);
}

async function load() {
  try {
    const resp = await fetch("./descriptor.v1.json", { cache: "no-store" });
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    const d = await resp.json();
    state.descriptor = d;

    // Load metaschemas for schema documentation pages.
    const schemaEntries = Object.entries(SCHEMA_FILES);
    await Promise.all(schemaEntries.map(async ([kind, filename]) => {
      const r = await fetch(`./metaschema/${filename}`, { cache: "no-store" });
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      state.schemas[kind] = await r.json();
    }));

    const v = d.version || {};
    $("version").textContent = `v${v.spec_version || "?"}`;
    setStatus("Loaded.");
    render();
  } catch (e) {
    setStatus(`Failed to load docs data: ${e.message}`, true);
  }
}

window.addEventListener("hashchange", () => render());
document.addEventListener("DOMContentLoaded", () => {
  const s = $("search");
  s.addEventListener("input", () => {
    state.query = s.value || "";
    render();
  });
  load();
});
