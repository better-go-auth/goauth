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

  const createRes = await owner.organization.create({ name: "Acme Corp", slug: `acme-${ts}`, metadata: { plan: "pro" } });
  assert(!createRes.error && createRes.data?.id, `organization.create failed: ${JSON.stringify(createRes.error)}`);
  const org = createRes.data;
  console.log("Created org:", org.id, org.name);
  // better-auth shape: the organization with the creator's membership and object metadata
  assert(Array.isArray(org.members) && org.members.length === 1 && org.members[0].role === "owner", `create should return members: ${JSON.stringify(org)}`);
  assert(org.metadata?.plan === "pro", `create should return metadata as an object: ${JSON.stringify(org.metadata)}`);

  // Slug is now taken
  const slugTaken = await owner.organization.checkSlug({ slug: `acme-${ts}` });
  assert(slugTaken.error?.code === "ORGANIZATION_SLUG_ALREADY_TAKEN", `expected ORGANIZATION_SLUG_ALREADY_TAKEN: ${JSON.stringify(slugTaken.error)}`);

  // 3. Get full org, list orgs, update org, setActive
  console.log("\n[3] Testing getFullOrganization, list, update, setActive...");
  const fullOrg = await owner.organization.getFullOrganization({ query: { organizationId: org.id } });
  assert(!fullOrg.error && fullOrg.data?.id === org.id, `getFullOrganization failed: ${JSON.stringify(fullOrg.error)}`);
  assert(
    fullOrg.data.members?.length === 1 && fullOrg.data.members[0].user?.email === ownerEmail && Array.isArray(fullOrg.data.invitations) && Array.isArray(fullOrg.data.teams),
    `getFullOrganization should include members (with user), invitations and teams: ${JSON.stringify(fullOrg.data)}`
  );

  const listRes = await owner.organization.list();
  assert(!listRes.error && Array.isArray(listRes.data) && listRes.data.length >= 1, `list failed: ${JSON.stringify(listRes)}`);

  const updateRes = await owner.organization.update({
    organizationId: org.id,
    data: { name: "Acme Updated" },
  });
  assert(!updateRes.error && updateRes.data?.name === "Acme Updated", `update failed: ${JSON.stringify(updateRes)}`);

  const setActiveRes = await owner.organization.setActive({ organizationSlug: `acme-${ts}` });
  assert(!setActiveRes.error && setActiveRes.data?.id === org.id, `setActive by slug should return the organization: ${JSON.stringify(setActiveRes)}`);

  // New better-auth routes on the active organization
  const ownerActive = await owner.organization.getActiveMember();
  assert(
    !ownerActive.error && ownerActive.data?.organizationId === org.id && ownerActive.data?.role === "owner" && ownerActive.data?.user?.email === ownerEmail,
    `getActiveMember failed: ${JSON.stringify(ownerActive)}`
  );
  const ownerRole = await owner.organization.getActiveMemberRole();
  assert(!ownerRole.error && ownerRole.data?.role === "owner", `getActiveMemberRole failed: ${JSON.stringify(ownerRole)}`);

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

  // Verified invitee can check inbox via listUserInvitations (enriched with organizationName, slug, inviter)
  const inboxRes = await invitee.organization.listUserInvitations();
  assert(!inboxRes.error && Array.isArray(inboxRes.data), `listUserInvitations failed: ${JSON.stringify(inboxRes)}`);
  const inboxInv = inboxRes.data.find((i) => i.id === inv2.id);
  assert(
    inboxInv &&
      inboxInv.organizationName === "Acme Updated" &&
      inboxInv.organizationSlug === `acme-${ts}` &&
      inboxInv.inviter?.email === ownerEmail,
    `expected enriched invitation in listUserInvitations, got: ${JSON.stringify(inboxRes.data)}`
  );

  // Verified invitee can now getInvitation and acceptInvitation
  const getInvOk = await invitee.organization.getInvitation({ query: { id: inv2.id } });
  assert(!getInvOk.error && getInvOk.data?.id === inv2.id, `verified getInvitation failed: ${JSON.stringify(getInvOk.error)}`);
  assert(
    getInvOk.data.organizationName === "Acme Updated" && getInvOk.data.organizationSlug === `acme-${ts}` && getInvOk.data.inviterEmail === ownerEmail,
    `getInvitation should include organizationName, organizationSlug and inviterEmail: ${JSON.stringify(getInvOk.data)}`
  );

  // Before accepting, the invitee has no active organization
  const noActive = await invitee.organization.getActiveMember();
  assert(noActive.error?.code === "NO_ACTIVE_ORGANIZATION", `expected NO_ACTIVE_ORGANIZATION: ${JSON.stringify(noActive)}`);

  const acceptOk = await invitee.organization.acceptInvitation({ invitationId: inv2.id });
  assert(!acceptOk.error, `verified acceptInvitation failed: ${JSON.stringify(acceptOk.error)}`);
  assert(
    acceptOk.data?.invitation?.status === "accepted" && acceptOk.data?.member?.role === "admin",
    `acceptInvitation should return {invitation, member}: ${JSON.stringify(acceptOk.data)}`
  );

  // Accepting made the organization active for the invitee
  const inviteeActive = await invitee.organization.getActiveMember();
  assert(
    !inviteeActive.error && inviteeActive.data?.userId === inviteeUserId && inviteeActive.data?.role === "admin",
    `invitee getActiveMember failed: ${JSON.stringify(inviteeActive)}`
  );
  const ownerRoleByQuery = await invitee.organization.getActiveMemberRole({
    query: { organizationId: org.id, userId: ownerActive.data.userId },
  });
  assert(!ownerRoleByQuery.error && ownerRoleByQuery.data?.role === "owner", `getActiveMemberRole with query failed: ${JSON.stringify(ownerRoleByQuery)}`);

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

  // Only team members may list a team's members (better-auth): the owner is not in team2
  const listTmDenied = await owner.organization.listTeamMembers({ query: { teamId: team2.id } });
  assert(listTmDenied.error?.code === "USER_IS_NOT_A_MEMBER_OF_THE_TEAM", `expected USER_IS_NOT_A_MEMBER_OF_THE_TEAM: ${JSON.stringify(listTmDenied)}`);

  const userTeams = await invitee.organization.listUserTeams();
  assert(
    !userTeams.error && Array.isArray(userTeams.data) && userTeams.data.length === 1 && userTeams.data[0].id === team2.id,
    `listUserTeams failed: ${JSON.stringify(userTeams)}`
  );

  const listTmRes = await invitee.organization.listTeamMembers({
    query: { teamId: team2.id },
  });
  assert(
    !listTmRes.error && Array.isArray(listTmRes.data) && listTmRes.data.length === 1 && listTmRes.data[0].user?.email === inviteeEmail,
    `listTeamMembers failed or missing preloaded user: ${JSON.stringify(listTmRes)}`
  );

  const setActiveTeamRes = await invitee.organization.setActiveTeam({ teamId: team2.id });
  assert(!setActiveTeamRes.error && setActiveTeamRes.data?.id === team2.id, `setActiveTeam should return the team: ${JSON.stringify(setActiveTeamRes)}`);

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

  // Regular "member" can call listMembers
  const memListByMember = await invitee.organization.listMembers({ query: { organizationId: org.id } });
  assert(!memListByMember.error && memListByMember.data?.members?.length === 2, `member listMembers failed: ${JSON.stringify(memListByMember)}`);

  const roleAfterUpdate = await invitee.organization.getActiveMemberRole();
  assert(!roleAfterUpdate.error && roleAfterUpdate.data?.role === "member", `getActiveMemberRole after update failed: ${JSON.stringify(roleAfterUpdate)}`);

  // Sole owner cannot leave organization
  const soleOwnerLeave = await owner.organization.leave({ organizationId: org.id });
  assert(
    soleOwnerLeave.error?.code === "YOU_CANNOT_LEAVE_THE_ORGANIZATION_AS_THE_ONLY_OWNER",
    `expected sole owner leave to fail: ${JSON.stringify(soleOwnerLeave.error)}`
  );

  const rmMemRes = await owner.organization.removeMember({
    memberIdOrEmail: inviteeEmail,
    organizationId: org.id,
  });
  assert(!rmMemRes.error && rmMemRes.data?.member?.userId === inviteeUserId, `removeMember by email failed: ${JSON.stringify(rmMemRes)}`);

  // The removed member is no longer a member of the organization
  const roleAfterRemoval = await invitee.organization.getActiveMemberRole({ query: { organizationId: org.id } });
  assert(
    roleAfterRemoval.error?.code === "YOU_ARE_NOT_A_MEMBER_OF_THIS_ORGANIZATION" && roleAfterRemoval.error?.status === 403,
    `expected YOU_ARE_NOT_A_MEMBER_OF_THIS_ORGANIZATION: ${JSON.stringify(roleAfterRemoval)}`
  );

  // 7. OrganizationLimit (max 2) + Self-Service LeaveOrganization
  console.log("\n[7] Testing OrganizationLimit=2 & leave...");
  const org2Res = await owner.organization.create({ name: "Second Org", slug: `second-${ts}` });
  assert(!org2Res.error && org2Res.data?.id, `2nd org create failed: ${JSON.stringify(org2Res.error)}`);

  const invOrg2 = await owner.organization.inviteMember({
    email: inviteeEmail,
    role: "member",
    organizationId: org2Res.data.id,
  });
  assert(!invOrg2.error && invOrg2.data?.id, `invite to org2 failed: ${JSON.stringify(invOrg2.error)}`);
  const acceptOrg2 = await invitee.organization.acceptInvitation({ invitationId: invOrg2.data.id });
  assert(!acceptOrg2.error, `accept org2 failed: ${JSON.stringify(acceptOrg2.error)}`);
  const leaveOrg2 = await invitee.organization.leave({ organizationId: org2Res.data.id });
  assert(!leaveOrg2.error, `invitee leave org2 failed: ${JSON.stringify(leaveOrg2.error)}`);

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

