// Creates better-auth's own database schema (better-auth 1.6.16, Kysely migrations on an in-memory SQLite
// database) for the core tables and every plugin goauth implements, then prints it as JSON:
// { tables: { <name>: { columns: [{name, type, notnull, pk}], indexes: [{name, unique, columns}],
//   foreignKeys: [{from, table, to, onDelete}] } }, defaults: { <table>: [columns with a defaultValue] } }.
// Used by src/tests/compat/schemaparity to compare goauth's ColumnCase "camel" schema with better-auth's.
import Database from "better-sqlite3";
import { getAuthTables } from "better-auth/db";
import { getMigrations } from "better-auth/db/migration";
import {
	admin,
	anonymous,
	bearer,
	deviceAuthorization,
	emailOTP,
	genericOAuth,
	jwt,
	magicLink,
	multiSession,
	oneTimeToken,
	organization,
	phoneNumber,
	siwe,
	twoFactor,
	username,
} from "better-auth/plugins";

// Step 1: the passkey plugin is a separate package (installed in ../client-passkey)
let passkeyPlugin = null;
try {
	const mod = await import("../client-passkey/node_modules/@better-auth/passkey/dist/index.mjs");
	passkeyPlugin = mod.passkey();
} catch {
	// without client-passkey/node_modules the passkey table is left out (the Go test notices)
}

// Step 2: better-auth's options with every plugin goauth implements
const db = new Database(":memory:");
const options = {
	database: db,
	secret: "schema-dump-secret-schema-dump-secret",
	baseURL: "http://localhost:3000",
	emailAndPassword: { enabled: true },
	rateLimit: { storage: "database" },
	plugins: [
		admin(),
		anonymous(),
		bearer(),
		// better-auth 1.6.16 parses `schema` as required, so it is passed explicitly
		deviceAuthorization({ schema: {} }),
		emailOTP({ sendVerificationOTP: async () => {} }),
		genericOAuth({ config: [] }),
		jwt(),
		magicLink({ sendMagicLink: async () => {} }),
		multiSession(),
		oneTimeToken(),
		organization({ teams: { enabled: true }, dynamicAccessControl: { enabled: true } }),
		phoneNumber({ sendOTP: async () => {} }),
		siwe({ domain: "localhost:3000", getNonce: async () => "nonce1234", verifyMessage: async () => true }),
		twoFactor(),
		username(),
		...(passkeyPlugin ? [passkeyPlugin] : []),
	],
	logger: { disabled: true },
};

// Step 3: run better-auth's migrations
const { runMigrations } = await getMigrations(options);
await runMigrations();

// Step 4: dump tables, columns, indexes and foreign keys; "defaults" lists the fields whose value
// better-auth's adapter always fills (defaultValue), per table
const out = { tables: {}, defaults: {}, passkey: Boolean(passkeyPlugin) };
for (const [model, def] of Object.entries(getAuthTables(options))) {
	const table = def.modelName || model;
	out.defaults[table] = Object.entries(def.fields)
		.filter(([, f]) => f.defaultValue !== undefined)
		.map(([name, f]) => f.fieldName || name);
}
const tables = db.prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'").all();
for (const { name } of tables) {
	const q = (s) => `"${s.replaceAll('"', '""')}"`;
	const columns = db.prepare(`PRAGMA table_info(${q(name)})`).all().map((c) => ({
		name: c.name,
		type: c.type,
		notnull: c.notnull === 1,
		pk: c.pk > 0,
	}));
	const indexes = db.prepare(`PRAGMA index_list(${q(name)})`).all().map((i) => ({
		name: i.name,
		unique: i.unique === 1,
		columns: db.prepare(`PRAGMA index_info(${q(i.name)})`).all().map((c) => c.name),
	}));
	const foreignKeys = db.prepare(`PRAGMA foreign_key_list(${q(name)})`).all().map((f) => ({
		from: f.from,
		table: f.table,
		to: f.to,
		onDelete: f.on_delete,
	}));
	out.tables[name] = { columns, indexes, foreignKeys };
}
console.log(JSON.stringify(out));
