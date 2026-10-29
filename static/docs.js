"use strict";
// API docs page. Fetches the OpenAPI document Dropshot generates
// (/openapi.json) and renders it. Plain JS, no build step.
//
// The pure helpers at the top are unit tested with `node --test static/`.
// `start` wires them to the page and only runs in a browser. Text from the
// document reaches the page through `textContent`, never parsed as HTML.

(function () {
  const LOCAL_REF = "#/";

  // Pure helpers

  /** Follow a local `$ref` (`#/a/b`) in `doc`. Anything else is returned as is. */
  function resolve(doc, value) {
    if (!value || typeof value.$ref !== "string") {
      return value;
    }
    if (!value.$ref.startsWith(LOCAL_REF)) {
      return undefined;
    }
    let node = doc;
    for (const part of value.$ref.slice(LOCAL_REF.length).split("/")) {
      if (node === null || typeof node !== "object" || !Object.hasOwn(node, part)) {
        return undefined;
      }
      node = node[part];
    }
    return node;
  }

  /** "#/components/schemas/Thing" -> "Thing". */
  function refName(ref) {
    return typeof ref === "string" ? ref.slice(ref.lastIndexOf("/") + 1) : "";
  }

  /** A short type description: "string", "array of Thing", "\"a\" | \"b\"". */
  function typeLabel(schema) {
    if (!schema) {
      return "any";
    }
    if (schema.$ref) {
      return refName(schema.$ref);
    }
    if (Array.isArray(schema.allOf) && schema.allOf.length === 1) {
      return typeLabel(schema.allOf[0]);
    }
    let label;
    if (Array.isArray(schema.enum)) {
      label = schema.enum.map((v) => JSON.stringify(v)).join(" | ");
    } else if (schema.type === "array") {
      label = "array of " + typeLabel(schema.items);
    } else if (schema.type) {
      label = schema.format ? `${schema.type} (${schema.format})` : schema.type;
    } else if (Array.isArray(schema.oneOf) || Array.isArray(schema.anyOf)) {
      label = (schema.oneOf || schema.anyOf).map(typeLabel).join(" | ");
    } else {
      label = "any";
    }
    return schema.nullable ? label + " or null" : label;
  }

  /** The properties of an object schema, sorted by name. */
  function fields(schema) {
    if (!schema || !schema.properties) {
      return [];
    }
    const required = new Set(schema.required || []);
    return Object.keys(schema.properties)
      .sort()
      .map((name) => {
        const property = schema.properties[name];
        return {
          name,
          type: typeLabel(property),
          required: required.has(name),
          description: property.description || "",
        };
      });
  }

  /** The `oneOf` alternatives of a schema, each with its own fields. */
  function variants(schema) {
    if (!schema || !Array.isArray(schema.oneOf)) {
      return [];
    }
    return schema.oneOf.map((variant) => ({
      description: variant.description || "",
      type: variant.properties ? "" : typeLabel(variant),
      fields: fields(variant),
    }));
  }

  function bodyType(doc, body) {
    const resolved = resolve(doc, body);
    const content = resolved && resolved.content && resolved.content["application/json"];
    return content ? typeLabel(content.schema) : "";
  }

  /** Every operation, sorted by path then method, with references resolved. */
  function operations(doc) {
    const out = [];
    const paths = (doc && doc.paths) || {};
    for (const path of Object.keys(paths).sort()) {
      const item = paths[path];
      for (const method of Object.keys(item).sort()) {
        const op = item[method];
        out.push({
          method: method.toUpperCase(),
          path,
          summary: op.summary || "",
          description: op.description || "",
          parameters: (op.parameters || []).map((p) => {
            const param = resolve(doc, p);
            return {
              name: param.name,
              in: param.in,
              type: typeLabel(param.schema),
              required: Boolean(param.required),
            };
          }),
          requestBody: bodyType(doc, op.requestBody),
          responses: Object.keys(op.responses || {})
            .sort()
            .map((status) => {
              const response = resolve(doc, op.responses[status]) || {};
              return {
                status,
                description: response.description || "",
                type: bodyType(doc, response),
              };
            }),
        });
      }
    }
    return out;
  }

  /** Names of the schemas in `components`, sorted. */
  function schemaNames(doc) {
    const schemas = doc && doc.components && doc.components.schemas;
    return schemas ? Object.keys(schemas).sort() : [];
  }

  /** Fragment id for a schema's section. */
  function anchor(name) {
    return "schema-" + name;
  }

  // Page

  function start(doc, win) {
    const el = (tag, className, text) => {
      const node = doc.createElement(tag);
      if (className) {
        node.className = className;
      }
      if (text !== undefined) {
        node.textContent = text;
      }
      return node;
    };

    /** A type label, linked to its schema when it names one. */
    const typeNode = (spec, label) => {
      const names = new Set(schemaNames(spec));
      const bare = label.replace(/^array of /, "").replace(/ or null$/, "");
      if (!names.has(bare)) {
        return el("code", "", label);
      }
      const link = el("a", "", label);
      link.href = "#" + anchor(bare);
      const code = el("code");
      code.append(link);
      return code;
    };

    const fieldTable = (spec, rows) => {
      const table = el("table", "fields");
      const head = el("tr");
      for (const title of ["Field", "Type", "Description"]) {
        head.append(el("th", "", title));
      }
      table.append(head);
      for (const row of rows) {
        const tr = el("tr");
        tr.append(el("td", "", row.required ? row.name : row.name + "?"));
        const type = el("td");
        type.append(typeNode(spec, row.type));
        tr.append(type);
        tr.append(el("td", "", row.description));
        table.append(tr);
      }
      return table;
    };

    const keyValue = (spec, key, label) => {
      const line = el("div", "kv");
      line.append(el("span", "k", key + " "));
      line.append(label ? typeNode(spec, label) : el("span", "", "none"));
      return line;
    };

    const renderOperation = (spec, op) => {
      const panel = el("section", "panel op");
      const title = el("div", "op-title");
      title.append(el("span", "pill method", op.method));
      title.append(el("code", "path", op.path));
      panel.append(title);
      if (op.summary) {
        panel.append(el("p", "", op.summary));
      }
      if (op.description) {
        panel.append(el("p", "note", op.description));
      }
      for (const param of op.parameters) {
        panel.append(keyValue(spec, `${param.in} ${param.name}`, param.type));
      }
      if (op.requestBody) {
        panel.append(keyValue(spec, "Body", op.requestBody));
      }
      for (const response of op.responses) {
        const line = keyValue(spec, response.status, response.type);
        line.append(el("span", "note", " " + response.description));
        panel.append(line);
      }
      return panel;
    };

    const renderSchema = (spec, name) => {
      const schema = spec.components.schemas[name];
      const panel = el("section", "panel schema");
      panel.id = anchor(name);
      panel.append(el("div", "section-title", name));
      if (schema.description) {
        panel.append(el("p", "", schema.description));
      }
      const own = fields(schema);
      if (own.length > 0) {
        panel.append(fieldTable(spec, own));
      } else if (!schema.oneOf) {
        panel.append(keyValue(spec, "Type", typeLabel(schema)));
      }
      variants(schema).forEach((variant, i) => {
        panel.append(el("div", "k", `One of (${i + 1}): ${variant.description}`));
        if (variant.fields.length > 0) {
          panel.append(fieldTable(spec, variant.fields));
        } else {
          panel.append(keyValue(spec, "Type", variant.type));
        }
      });
      return panel;
    };

    const status = doc.getElementById("docs-message");
    const operationsNode = doc.getElementById("operations");
    const schemasNode = doc.getElementById("schemas");

    win
      .fetch("/openapi.json", { headers: { accept: "application/json" } })
      .then((response) => {
        if (!response.ok) {
          throw new Error(`HTTP ${response.status}`);
        }
        return response.json();
      })
      .then((spec) => {
        doc.getElementById("api-title").textContent = `${spec.info.title} ${spec.info.version}`;
        doc.getElementById("api-description").textContent = spec.info.description || "";
        for (const op of operations(spec)) {
          operationsNode.append(renderOperation(spec, op));
        }
        for (const name of schemaNames(spec)) {
          schemasNode.append(renderSchema(spec, name));
        }
        status.textContent = "";
      })
      .catch((error) => {
        status.textContent = "Could not load /openapi.json: " + error.message;
      });
  }

  const api = {
    resolve,
    refName,
    typeLabel,
    fields,
    variants,
    operations,
    schemaNames,
    anchor,
    start,
  };

  if (typeof module === "object" && module.exports) {
    module.exports = api;
  } else {
    document.addEventListener("DOMContentLoaded", () => start(document, window));
  }
})();
