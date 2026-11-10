import { createAuthClient } from "better-auth/client";
import { organizationClient } from "better-auth/client/plugins";

const baseURL = process.env.GOAUTH_URL || "http://127.0.0.1:8080";
const restrictedURL = process.env.GOAUTH_RESTRICTED_URL || "";
const restrictedOrgID = process.env.GOAUTH_RESTRICTED_ORG_ID || "";

console.log("Running official better-auth/client Organization test against:", baseURL);

function makeClient(url) {
  let bearerToken = "";
  const cookies = new Map();

  function getCookieHeader() {
    return Array.from(cookies.entries())
      .map(([k, v]) => `${k}=${v}`)
      .join("; ");
  }

  function saveCookies(response) {
    const getSetCookie = response.headers.getSetCookie?.() || [];
    if (getSetCookie.length === 0) {
      const raw = response.headers.get("set-cookie");
      if (raw) getSetCookie.push(raw);
    }
    for (const str of getSetCookie) {
      const parts = str.split(";")[0].split("=");
      const name = parts[0]?.trim();
      const value = parts.slice(1).join("=").trim();
      if (name) {
        if (str.includes("Max-Age=0")) cookies.delete(name);
        else cookies.set(name, value);
      }
    }
  }

  const client = createAuthClient({
    baseURL: url,
    plugins: [
      organizationClient({
        teams: { enabled: true },
      }),
    ],
    fetchOptions: {
      auth: {
        type: "Bearer",
        token: () => bearerToken,
      },
      onRequest(ctx) {
        ctx.headers.set("origin", url);
        const c = getCookieHeader();
        if (c) ctx.headers.set("cookie", c);
      },
      onResponse(ctx) {
        saveCookies(ctx.response);
        const tok = ctx.response.headers.get("set-auth-token");
        if (tok) bearerToken = tok;
      },
    },
  });

  return { client, getToken: () => bearerToken };
}

function assert(cond, msg) {
  if (!cond) {
    console.error("ASSERTION FAILED:", msg);
    process.exit(1);
  }
}

async function main() {
  const ts = Date.now();
  const ownerEmail = `org-owner-${ts}@example.com`;
  const inviteeEmail = `org-invitee-${ts}@example.com`;
  const password = "Password123!";

  const { client: owner } = makeClient(baseURL);
  const { client: invitee } = makeClient(baseURL);

  // 1. Register Owner and Invitee
  console.log("\n[1] Signing up owner and invitee...");
  const ownerUp = await owner.signUp.email({ email: ownerEmail, password, name: "Org Owner" });
  assert(!ownerUp.error, `owner signUp failed: ${JSON.stringify(ownerUp.error)}`);

  const inviteeUp = await invitee.signUp.email({ email: inviteeEmail, password, name: "Org Invitee" });
  assert(!inviteeUp.error, `invitee signUp failed: ${JSON.stringify(inviteeUp.error)}`);
  const inviteeUserId = inviteeUp.data.user.id;

  // 2. Check slug & create organization
  console.log("\n[2] Checking slug & creating organization...");
  const slugOk = await owner.organization.checkSlug({ slug: `acme-${ts}` });
  assert(!slugOk.error && slugOk.data?.status === true, `checkSlug expected true: ${JSON.stringify(slugOk)}`);

  const createRes = await owner.organization.create({ name: "Acme Corp", slug: `acme-${ts}` });
  assert(!createRes.error && createRes.data?.id, `organization.create failed: ${JSON.stringify(createRes.error)}`);
  const org = createRes.data;
  console.log("Created org:", org.id, org.name);

  // Slug is now taken
  const slugTaken = await owner.organization.checkSlug({ slug: `acme-${ts}` });
  assert(slugTaken.error, "expected checkSlug to fail for existing slug");

  // 3. Get full org, list orgs, update org, setActive
  console.log("\n[3] Testing getFullOrganization, list, update, setActive...");
  const fullOrg = await owner.organization.getFullOrganization({ query: { organizationId: org.id } });
  assert(!fullOrg.error && fullOrg.data?.id === org.id, `getFullOrganization failed: ${JSON.stringify(fullOrg.error)}`);

  const listRes = await owner.organization.list();
  assert(!listRes.error && listRes.data?.organizations?.length >= 1, `list failed: ${JSON.stringify(listRes)}`);

  const updateRes = await owner.organization.update({
    organizationId: org.id,
    data: { name: "Acme Updated" },
  });
  assert(!updateRes.error && updateRes.data?.name === "Acme Updated", `update failed: ${JSON.stringify(updateRes)}`);

  const setActiveRes = await owner.organization.setActive({ organizationSlug: `acme-${ts}` });
  assert(!setActiveRes.error, `setActive by slug failed: ${JSON.stringify(setActiveRes.error)}`);

  // 4. Teams: custom default team + createTeam + MaximumTeams + updateTeam
  console.log("\n[4] Testing Teams (custom default team, limits, updateTeam)...");
  const initialTeams = await owner.organization.listTeams({ query: { organizationId: org.id } });
  assert(!initialTeams.error && initialTeams.data?.length === 1, `expected 1 default team, got: ${JSON.stringify(initialTeams)}`);
  assert(initialTeams.data[0].name === "Core-Acme Corp", `expected custom default team 'Core-Acme Corp', got: ${initialTeams.data[0].name}`);

  const team2Res = await owner.organization.createTeam({ name: "Engineering", organizationId: org.id });
  assert(!team2Res.error && team2Res.data?.id, `createTeam failed: ${JSON.stringify(team2Res.error)}`);
  const team2 = team2Res.data;

  // 3rd team must exceed MaximumTeams=2
  const team3Res = await owner.organization.createTeam({ name: "TooMany", organizationId: org.id });
  assert(team3Res.error, "expected 3rd team to fail due to MaximumTeams=2");

  const updateTeamRes = await owner.organization.updateTeam({
    teamId: team2.id,
    data: { name: "Platform" },
  });
  assert(!updateTeamRes.error && updateTeamRes.data?.name === "Platform", `updateTeam failed: ${JSON.stringify(updateTeamRes)}`);

  // 5. Invitations: CancelPendingInvitationsOnReInvite & RequireEmailVerificationOnInvitation
  console.log("\n[5] Testing Invitations (re-invite cancellation + email verification gate)...");
  const inv1Res = await owner.organization.inviteMember({
    email: inviteeEmail,
    role: "member",
    organizationId: org.id,
  });
  assert(!inv1Res.error && inv1Res.data?.id, `inviteMember 1 failed: ${JSON.stringify(inv1Res.error)}`);

  // Re-invite same email -> cancels inv1 and creates inv2
  const inv2Res = await owner.organization.inviteMember({
    email: inviteeEmail,
    role: "admin",
    organizationId: org.id,
  });
  assert(!inv2Res.error && inv2Res.data?.id && inv2Res.data.id !== inv1Res.data.id, `re-invite failed: ${JSON.stringify(inv2Res)}`);
  const inv2 = inv2Res.data;

  // Unverified invitee cannot getInvitation or acceptInvitation
  const getInvDenied = await invitee.organization.getInvitation({ query: { id: inv2.id } });
  assert(getInvDenied.error, "expected unverified invitee getInvitation to be rejected");

  const acceptDenied = await invitee.organization.acceptInvitation({ invitationId: inv2.id });
  assert(acceptDenied.error, "expected unverified invitee acceptInvitation to be rejected");

  // Mark invitee verified via test helper endpoint
  const verifyResp = await fetch(`${baseURL}/test/verify-user?userId=${encodeURIComponent(inviteeUserId)}`, { method: "POST" });
  assert(verifyResp.ok, "test helper /test/verify-user failed");

  // Verified invitee can now getInvitation and acceptInvitation
  const getInvOk = await invitee.organization.getInvitation({ query: { id: inv2.id } });
  assert(!getInvOk.error && getInvOk.data?.id === inv2.id, `verified getInvitation failed: ${JSON.stringify(getInvOk.error)}`);

  const acceptOk = await invitee.organization.acceptInvitation({ invitationId: inv2.id });
  assert(!acceptOk.error, `verified acceptInvitation failed: ${JSON.stringify(acceptOk.error)}`);

  // 6. Members & Team Members
  console.log("\n[6] Testing Members & Team Members...");
  const membersRes = await owner.organization.listMembers({ query: { organizationId: org.id } });
  assert(!membersRes.error && membersRes.data?.members?.length === 2, `listMembers failed: ${JSON.stringify(membersRes)}`);
  const inviteeMember = membersRes.data.members.find((m) => m.userId === inviteeUserId);
  assert(inviteeMember && inviteeMember.role === "admin", `expected invitee role 'admin', got: ${JSON.stringify(inviteeMember)}`);

  const addTmRes = await owner.organization.addTeamMember({
    teamId: team2.id,
    userId: inviteeUserId,
    organizationId: org.id,
  });
  assert(!addTmRes.error, `addTeamMember failed: ${JSON.stringify(addTmRes.error)}`);

  const setActiveTeamRes = await invitee.organization.setActiveTeam({ teamId: team2.id });
  assert(!setActiveTeamRes.error, `setActiveTeam failed: ${JSON.stringify(setActiveTeamRes.error)}`);

  const rmTmRes = await owner.organization.removeTeamMember({
    teamId: team2.id,
    userId: inviteeUserId,
    organizationId: org.id,
  });
  assert(!rmTmRes.error, `removeTeamMember failed: ${JSON.stringify(rmTmRes.error)}`);

  const rmTeamRes = await owner.organization.removeTeam({ teamId: team2.id, organizationId: org.id });
  assert(!rmTeamRes.error, `removeTeam failed: ${JSON.stringify(rmTeamRes.error)}`);

  const updRoleRes = await owner.organization.updateMemberRole({
    memberId: inviteeMember.id,
    role: "member",
    organizationId: org.id,
  });
  assert(!updRoleRes.error && updRoleRes.data?.role === "member", `updateMemberRole failed: ${JSON.stringify(updRoleRes)}`);

  const rmMemRes = await owner.organization.removeMember({
    memberIdOrEmail: inviteeEmail,
    organizationId: org.id,
  });
  assert(!rmMemRes.error, `removeMember by email failed: ${JSON.stringify(rmMemRes.error)}`);

  // 7. OrganizationLimit (max 2)
  console.log("\n[7] Testing OrganizationLimit=2...");
  const org2Res = await owner.organization.create({ name: "Second Org", slug: `second-${ts}` });
  assert(!org2Res.error && org2Res.data?.id, `2nd org create failed: ${JSON.stringify(org2Res.error)}`);

  const org3Res = await owner.organization.create({ name: "Third Org", slug: `third-${ts}` });
  assert(org3Res.error, "expected 3rd org creation to fail due to OrganizationLimit=2");

  // 8. Delete organization via POST /organization/delete
  console.log("\n[8] Testing organization.delete...");
  const delRes = await owner.organization.delete({ organizationId: org.id });
  assert(!delRes.error, `organization.delete failed: ${JSON.stringify(delRes.error)}`);

  // 9. Restricted server checks (AllowUserToCreateOrganization=false, DisableOrganizationDeletion=true)
  if (restrictedURL) {
    console.log("\n[9] Testing AllowUserToCreateOrganization=false & DisableOrganizationDeletion=true...");
    const { client: restrictedClient } = makeClient(restrictedURL);
    const upRes = await restrictedClient.signUp.email({
      email: `restricted-${ts}@example.com`,
      password,
      name: "Restricted User",
    });
    assert(!upRes.error, `restricted signUp failed: ${JSON.stringify(upRes.error)}`);

    const createBlocked = await restrictedClient.organization.create({
      name: "Blocked",
      slug: `blocked-${ts}`,
    });
    assert(createBlocked.error, "expected create org to fail when AllowUserToCreateOrganization=false");

    if (restrictedOrgID) {
      // Sign in as pre-seeded restricted org owner
      const { client: rOwner } = makeClient(restrictedURL);
      const inRes = await rOwner.signIn.email({
        email: "restricted-owner@example.com",
        password: "Password123!",
      });
      assert(!inRes.error, `restricted owner signIn failed: ${JSON.stringify(inRes.error)}`);

      const delBlocked = await rOwner.organization.delete({ organizationId: restrictedOrgID });
      assert(delBlocked.error, "expected delete org to fail when DisableOrganizationDeletion=true");
    }
  }

  console.log("\n✅ All official better-auth/client Organization plugin tests passed successfully!");
}

main().catch((err) => {
  console.error("Fatal test error:", err);
  process.exit(1);
});

