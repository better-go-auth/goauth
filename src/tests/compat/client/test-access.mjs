// Official better-auth client test for the access-control port (admin + organization).
// Run by TestOfficialBetterAuthClient_Access (access_official_test.go).
import { createAuthClient } from "better-auth/client";
import { adminClient, organizationClient } from "better-auth/client/plugins";
import { createAccessControl } from "better-auth/plugins/access";
import {
  defaultStatements as adminDefaultStatements,
  adminAc,
  userAc,
} from "better-auth/plugins/admin/access";
import {
  defaultStatements as orgDefaultStatements,
  ownerAc,
  adminAc as orgAdminAc,
  memberAc,
} from "better-auth/plugins/organization/access";

const baseURL = process.env.GOAUTH_URL || "http://127.0.0.1:8080";
const adminEmail = process.env.GOAUTH_ADMIN_EMAIL;
const supportEmail = process.env.GOAUTH_SUPPORT_EMAIL;
const password = process.env.GOAUTH_PASSWORD || "Password123!";

console.log("Running official better-auth/client access-control test against:", baseURL);

// Same roles as the Go server (access_official_test.go)
const adminAccess = createAccessControl(adminDefaultStatements);
const adminRoles = {
  admin: adminAc,
  user: userAc,
  support: adminAccess.newRole({ user: ["list", "get"] }),
};
const orgAccess = createAccessControl({ ...orgDefaultStatements, project: ["create", "read", "update", "delete"] });
const orgRoles = {
  owner: orgAccess.newRole({ ...ownerAc.statements, project: ["create", "read", "update", "delete"] }),
  admin: orgAccess.newRole({ ...orgAdminAc.statements, project: ["create", "read", "update"] }),
  member: orgAccess.newRole({ ...memberAc.statements, project: ["read"] }),
};

function makeClient() {
  let bearerToken = "";
  const client = createAuthClient({
    baseURL,
    plugins: [
      adminClient({ ac: adminAccess, roles: adminRoles }),
      organizationClient({ ac: orgAccess, roles: orgRoles, dynamicAccessControl: { enabled: true } }),
    ],
    fetchOptions: {
      auth: { type: "Bearer", token: () => bearerToken },
      onRequest(ctx) {
        ctx.headers.set("origin", baseURL);
      },
      onResponse(ctx) {
        const tok = ctx.response.headers.get("set-auth-token");
        if (tok) bearerToken = tok;
      },
    },
  });
  return client;
}

function assert(cond, msg) {
  if (!cond) {
    console.error("ASSERTION FAILED:", msg);
    process.exit(1);
  }
}

async function main() {
  const ts = Date.now();

  // [1] createAccessControl works client-side exactly like the Go port
  console.log("\n[1] createAccessControl / role.authorize...");
  const r = adminRoles.support.authorize({ user: ["list"] });
  assert(r.success === true, `support should list: ${JSON.stringify(r)}`);
  const denied = adminRoles.support.authorize({ user: ["ban"] });
  assert(!denied.success && denied.error === 'unauthorized to access resource "user"', `unexpected: ${JSON.stringify(denied)}`);

  // [2] admin.hasPermission for a regular user, the support role and the admin role
  console.log("\n[2] admin.hasPermission...");
  const user = makeClient();
  const up = await user.signUp.email({ email: `access-user-${ts}@example.com`, password, name: "Plain User" });
  assert(!up.error, `signUp failed: ${JSON.stringify(up.error)}`);
  const userPerm = await user.admin.hasPermission({ permissions: { user: ["list"] } });
  assert(!userPerm.error && userPerm.data?.success === false, `user should not list: ${JSON.stringify(userPerm)}`);
  const userList = await user.admin.listUsers({ query: { limit: 5 } });
  assert(userList.error?.code === "YOU_ARE_NOT_ALLOWED_TO_LIST_USERS", `expected list-users denial: ${JSON.stringify(userList.error)}`);

  const support = makeClient();
  const supportIn = await support.signIn.email({ email: supportEmail, password });
  assert(!supportIn.error, `support signIn failed: ${JSON.stringify(supportIn.error)}`);
  const supportPerm = await support.admin.hasPermission({ permissions: { user: ["list", "get"] } });
  assert(supportPerm.data?.success === true, `support should list+get: ${JSON.stringify(supportPerm)}`);
  const supportBan = await support.admin.hasPermission({ permissions: { user: ["ban"] } });
  assert(supportBan.data?.success === false, `support should not ban: ${JSON.stringify(supportBan)}`);
  const supportList = await support.admin.listUsers({ query: { limit: 5 } });
  assert(!supportList.error, `support listUsers failed: ${JSON.stringify(supportList.error)}`);

  const admin = makeClient();
  const adminIn = await admin.signIn.email({ email: adminEmail, password });
  assert(!adminIn.error, `admin signIn failed: ${JSON.stringify(adminIn.error)}`);
  const adminPerm = await admin.admin.hasPermission({ permissions: { user: ["ban"], session: ["revoke"] } });
  assert(adminPerm.data?.success === true, `admin should ban+revoke: ${JSON.stringify(adminPerm)}`);
  const impAdmins = await admin.admin.hasPermission({ permissions: { user: ["impersonate-admins"] } });
  assert(impAdmins.data?.success === false, `default admin lacks impersonate-admins: ${JSON.stringify(impAdmins)}`);
  // client-side check agrees with the server
  assert(admin.admin.checkRolePermission({ role: "admin", permissions: { user: ["ban"] } }) === true, "checkRolePermission admin");

  // [3] organization.hasPermission and dynamic role CRUD
  console.log("\n[3] organization.hasPermission / role CRUD...");
  const created = await user.organization.create({ name: "Access Org", slug: `access-org-${ts}` });
  assert(!created.error && created.data?.id, `org create failed: ${JSON.stringify(created.error)}`);
  const orgId = created.data.id;

  const ownerPerm = await user.organization.hasPermission({ organizationId: orgId, permissions: { project: ["delete"], ac: ["create"] } });
  assert(!ownerPerm.error && ownerPerm.data?.success === true, `owner should have project:delete: ${JSON.stringify(ownerPerm)}`);

  const role = await user.organization.createRole({ organizationId: orgId, role: "Reviewer", permission: { project: ["read", "update"] } });
  assert(!role.error && role.data?.success === true, `createRole failed: ${JSON.stringify(role.error)}`);
  assert(role.data.roleData.role === "reviewer", `role name should be lowercased: ${JSON.stringify(role.data)}`);
  assert(JSON.stringify(role.data.statements) === JSON.stringify({ project: ["read", "update"] }), `statements: ${JSON.stringify(role.data.statements)}`);

  const invalid = await user.organization.createRole({ organizationId: orgId, role: "biller", permission: { billing: ["read"] } });
  assert(invalid.error?.code === "INVALID_RESOURCE", `expected INVALID_RESOURCE: ${JSON.stringify(invalid.error)}`);
  const taken = await user.organization.createRole({ organizationId: orgId, role: "admin", permission: { project: ["read"] } });
  assert(taken.error?.code === "ROLE_NAME_IS_ALREADY_TAKEN", `expected ROLE_NAME_IS_ALREADY_TAKEN: ${JSON.stringify(taken.error)}`);

  const list = await user.organization.listRoles({ query: { organizationId: orgId } });
  assert(!list.error && Array.isArray(list.data) && list.data.length === 1, `listRoles: ${JSON.stringify(list)}`);
  const got = await user.organization.getRole({ query: { organizationId: orgId, roleName: "reviewer" } });
  assert(!got.error && got.data?.role === "reviewer", `getRole: ${JSON.stringify(got)}`);

  const updated = await user.organization.updateRole({ organizationId: orgId, roleName: "reviewer", data: { permission: { project: ["read"] } } });
  assert(!updated.error && updated.data?.success === true, `updateRole: ${JSON.stringify(updated.error)}`);

  const predefined = await user.organization.deleteRole({ organizationId: orgId, roleName: "member" });
  assert(predefined.error?.code === "CANNOT_DELETE_A_PRE_DEFINED_ROLE", `expected CANNOT_DELETE_A_PRE_DEFINED_ROLE: ${JSON.stringify(predefined.error)}`);
  const deleted = await user.organization.deleteRole({ organizationId: orgId, roleName: "reviewer" });
  assert(!deleted.error && deleted.data?.success === true, `deleteRole: ${JSON.stringify(deleted.error)}`);

  // a non-member gets USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION
  const outsider = await support.organization.hasPermission({ organizationId: orgId, permissions: { project: ["read"] } });
  assert(outsider.error?.code === "USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION", `expected non-member error: ${JSON.stringify(outsider.error)}`);

  console.log("\nAll access-control assertions passed");
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
