"use strict";
// Unit tests for the pure helpers in docs.js. Run with: node --test static/
// No dependencies: Node's built-in test runner and assert module only.

const test = require("node:test");
const assert = require("node:assert/strict");
const docs = require("./docs.js");

const DOC = {
  openapi: "3.0.3",
  info: { title: "totem", version: "0.1.0", description: "Test API." },
  components: {
    responses: {
      Error: {
        description: "Error",
        content: { "application/json": { schema: { $ref: "#/components/schemas/Error" } } },
      },
    },
    schemas: {
      Error: {
        type: "object",
        properties: { message: { type: "string" }, error_code: { type: "string" } },
        required: ["message"],
      },
      Thing: {
        description: "A thing.",
        type: "object",
        properties: {
          id: { type: "integer", format: "uint64", description: "Its ID." },
          tags: { type: "array", items: { type: "string" } },
          kind: { $ref: "#/components/schemas/Kind" },
          parts: { type: "array", items: { $ref: "#/components/schemas/Part" } },
          note: { nullable: true, type: "string" },
        },
        required: ["id", "kind"],
      },
      Kind: { type: "string", enum: ["a", "b"] },
      Part: {
        oneOf: [
          {
            description: "First variant.",
            type: "object",
            properties: { type: { type: "string", enum: ["one"] }, x: { type: "string" } },
            required: ["type", "x"],
          },
          {
            description: "Second variant.",
            type: "object",
            properties: { type: { type: "string", enum: ["two"] } },
            required: ["type"],
          },
        ],
        properties: { name: { type: "string" } },
        required: ["name"],
        type: "object",
      },
    },
  },
  paths: {
    "/things/{id}": {
      get: {
        operationId: "thing",
        summary: "Get a thing.",
        parameters: [
          {
            in: "path",
            name: "id",
            required: true,
            schema: { $ref: "#/components/schemas/Kind" },
          },
        ],
        responses: {
          200: {
            description: "successful operation",
            content: { "application/json": { schema: { $ref: "#/components/schemas/Thing" } } },
          },
          "4XX": { $ref: "#/components/responses/Error" },
        },
      },
    },
    "/things": {
      post: {
        operationId: "make",
        summary: "Make a thing.",
        requestBody: {
          required: true,
          content: { "application/json": { schema: { $ref: "#/components/schemas/Thing" } } },
        },
        responses: { 204: { description: "resource updated" } },
      },
      get: {
        operationId: "list",
        responses: { 200: { description: "ok" } },
      },
    },
  },
};

test("resolve follows local JSON pointers and leaves other values alone", () => {
  assert.equal(docs.resolve(DOC, { $ref: "#/components/schemas/Kind" }), DOC.components.schemas.Kind);
  assert.equal(
    docs.resolve(DOC, { $ref: "#/components/responses/Error" }).description,
    "Error",
  );
  const plain = { type: "string" };
  assert.equal(docs.resolve(DOC, plain), plain);
  assert.equal(docs.resolve(DOC, undefined), undefined);
});

test("resolve refuses missing and non-local references", () => {
  assert.equal(docs.resolve(DOC, { $ref: "#/components/schemas/Nope" }), undefined);
  assert.equal(docs.resolve(DOC, { $ref: "https://example.invalid/x.json" }), undefined);
});

test("refName is the last segment of a reference", () => {
  assert.equal(docs.refName("#/components/schemas/Thing"), "Thing");
  assert.equal(docs.refName(undefined), "");
});

test("typeLabel describes schemas briefly", () => {
  assert.equal(docs.typeLabel({ type: "string" }), "string");
  assert.equal(docs.typeLabel({ type: "integer", format: "uint64" }), "integer (uint64)");
  assert.equal(docs.typeLabel({ type: "array", items: { type: "string" } }), "array of string");
  assert.equal(docs.typeLabel({ $ref: "#/components/schemas/Thing" }), "Thing");
  assert.equal(
    docs.typeLabel({ type: "array", items: { $ref: "#/components/schemas/Part" } }),
    "array of Part",
  );
  assert.equal(docs.typeLabel({ type: "string", enum: ["a", "b"] }), '"a" | "b"');
  assert.equal(docs.typeLabel({ nullable: true, type: "string" }), "string or null");
  assert.equal(docs.typeLabel({ allOf: [{ $ref: "#/components/schemas/Kind" }] }), "Kind");
  assert.equal(docs.typeLabel({}), "any");
  assert.equal(docs.typeLabel(undefined), "any");
});

test("fields lists properties in name order with required flags", () => {
  assert.deepEqual(docs.fields(DOC.components.schemas.Thing), [
    { name: "id", type: "integer (uint64)", required: true, description: "Its ID." },
    { name: "kind", type: "Kind", required: true, description: "" },
    { name: "note", type: "string or null", required: false, description: "" },
    { name: "parts", type: "array of Part", required: false, description: "" },
    { name: "tags", type: "array of string", required: false, description: "" },
  ]);
  assert.deepEqual(docs.fields({ type: "string" }), []);
});

test("variants lists oneOf alternatives with their own fields", () => {
  const variants = docs.variants(DOC.components.schemas.Part);
  assert.equal(variants.length, 2);
  assert.equal(variants[0].description, "First variant.");
  assert.deepEqual(
    variants[0].fields.map((f) => [f.name, f.type, f.required]),
    [
      ["type", '"one"', true],
      ["x", "string", true],
    ],
  );
  assert.deepEqual(docs.variants(DOC.components.schemas.Thing), []);
});

test("operations are sorted by path then method, with refs resolved", () => {
  const ops = docs.operations(DOC);
  assert.deepEqual(
    ops.map((op) => [op.method, op.path]),
    [
      ["GET", "/things"],
      ["POST", "/things"],
      ["GET", "/things/{id}"],
    ],
  );
  const [list, make, get] = ops;
  assert.equal(list.summary, "");
  assert.equal(make.requestBody, "Thing");
  assert.equal(list.requestBody, "");
  assert.deepEqual(get.parameters, [{ name: "id", in: "path", type: "Kind", required: true }]);
  assert.deepEqual(get.responses, [
    { status: "200", description: "successful operation", type: "Thing" },
    { status: "4XX", description: "Error", type: "Error" },
  ]);
  assert.deepEqual(make.responses, [{ status: "204", description: "resource updated", type: "" }]);
});

test("operations of an empty document is empty", () => {
  assert.deepEqual(docs.operations({}), []);
});

test("schemaNames are sorted", () => {
  assert.deepEqual(docs.schemaNames(DOC), ["Error", "Kind", "Part", "Thing"]);
  assert.deepEqual(docs.schemaNames({}), []);
});

test("anchor makes a stable fragment id for a schema", () => {
  assert.equal(docs.anchor("Thing"), "schema-Thing");
});
