import { buildJwtAbility } from "@trigger.dev/plugins";
import { beforeEach, describe, expect, it, vi } from "vitest";

const bearerMocks = vi.hoisted(() => ({
  authenticateBearerWithTelemetry: vi.fn<(...args: any[]) => Promise<any>>(),
}));

vi.mock("~/services/authTelemetry.server", () => ({
  authenticateBearerWithTelemetry: bearerMocks.authenticateBearerWithTelemetry,
}));

import { getOneTimeUseToken } from "~/services/apiAuth.server";
import {
  authenticateRequestForApiBuilder,
  boundaryErrorLogValue,
  checkAuth,
  everyResource,
  presentedBearerToken,
  shouldRejectRestrictedKeyWithoutAuthorization,
} from "~/services/routeBuilders/apiBuilder.server";

describe("API boundary error logging", () => {
  it("redacts structurally recognized Drizzle query errors without changing them", () => {
    const query = "select * from secrets where token = $1";
    const params = ["secret-value"];
    const cause = { code: "23505", detail: "secret-detail" };
    const error = Object.assign(new Error(`Failed query: ${query}`), {
      query,
      params,
      cause,
    });
    error.stack = `Error: Failed query: ${query}\nsecret-stack`;

    expect(boundaryErrorLogValue(error)).toEqual({
      name: "DrizzleQueryError",
      message: "Database query failed",
      causeCode: "23505",
    });
    expect(error.message).toBe(`Failed query: ${query}`);
    expect(error.query).toBe(query);
    expect(error.params).toBe(params);
    expect(error.cause).toBe(cause);
  });

  it("omits non-scalar cause codes", () => {
    const error = Object.assign(new Error("Failed query: select 1"), {
      query: "select 1",
      params: [],
      cause: { code: { private: "value" } },
    });

    expect(boundaryErrorLogValue(error)).toEqual({
      name: "DrizzleQueryError",
      message: "Database query failed",
    });
  });
});

describe("restricted API key route authorization", () => {
  it("fails closed when a route has no authorization declaration", () => {
    expect(shouldRejectRestrictedKeyWithoutAuthorization(true, false)).toBe(true);
    expect(shouldRejectRestrictedKeyWithoutAuthorization(true, true)).toBe(false);
    expect(shouldRejectRestrictedKeyWithoutAuthorization(false, false)).toBe(false);
  });
});

describe("everyResource authorization", () => {
  it("requires an ID-scoped ability to match every requested resource", () => {
    const ability = buildJwtAbility(["read:tasks:task-a"]);

    expect(
      checkAuth(
        ability,
        "read",
        everyResource(
          [
            { type: "tasks", id: "task-a" },
            { type: "tasks", id: "task-b" },
          ],
          [{ type: "runs" }, { type: "tasks" }]
        )
      )
    ).toBe(false);
  });

  it("allows an ID-scoped ability when every requested resource matches", () => {
    const ability = buildJwtAbility(["read:tasks:task-a", "read:tasks:task-b"]);

    expect(
      checkAuth(
        ability,
        "read",
        everyResource(
          [
            { type: "tasks", id: "task-a" },
            { type: "tasks", id: "task-b" },
          ],
          [{ type: "runs" }, { type: "tasks" }]
        )
      )
    ).toBe(true);
  });

  it("preserves broad collection grants as an alternative", () => {
    const ability = buildJwtAbility(["read:runs"]);

    expect(
      checkAuth(
        ability,
        "read",
        everyResource(
          [
            { type: "tasks", id: "task-a" },
            { type: "tasks", id: "task-b" },
          ],
          [{ type: "runs" }, { type: "tasks" }]
        )
      )
    ).toBe(true);
  });
});


describe("authenticateRequestForApiBuilder — publicJWT one-time-use token identity", () => {
  const fakeEnv = {
    id: "env_123",
    apiKey: "tr_dev_shared_env_key",
    organizationId: "org_123",
    projectId: "proj_123",
  } as any;

  beforeEach(() => {
    bearerMocks.authenticateBearerWithTelemetry.mockReset();
  });

  it("preserves distinct presented public JWTs so getOneTimeUseToken produces distinct hashes", async () => {
    const ability = buildJwtAbility(["trigger:tasks:my-task"]);
    bearerMocks.authenticateBearerWithTelemetry.mockResolvedValue({
      ok: true,
      environment: fakeEnv,
      subject: {
        type: "publicJWT",
        environmentId: fakeEnv.id,
        organizationId: fakeEnv.organizationId,
        projectId: fakeEnv.projectId,
      },
      ability,
      jwt: { oneTimeUse: true },
    });

    const reqA = new Request("https://api.trigger.dev/api/v1/tasks/my-task/trigger", {
      method: "POST",
      headers: { Authorization: "Bearer eyJ.jwt.token.A" },
    });
    const reqB = new Request("https://api.trigger.dev/api/v1/tasks/my-task/trigger", {
      method: "POST",
      headers: { Authorization: "Bearer eyJ.jwt.token.B" },
    });

    const resA = await authenticateRequestForApiBuilder(reqA, { allowJWT: true });
    const resB = await authenticateRequestForApiBuilder(reqB, { allowJWT: true });

    expect(resA.ok).toBe(true);
    expect(resB.ok).toBe(true);
    if (!resA.ok || !resB.ok) throw new Error("unreachable");

    expect(resA.authentication.apiKey).toBe("eyJ.jwt.token.A");
    expect(resB.authentication.apiKey).toBe("eyJ.jwt.token.B");

    const hashA = await getOneTimeUseToken(resA.authentication);
    const hashB = await getOneTimeUseToken(resB.authentication);
    expect(hashA).toBeDefined();
    expect(hashB).toBeDefined();
    expect(hashA).not.toBe(hashB);

    const replayHashA = await getOneTimeUseToken(resA.authentication);
    expect(replayHashA).toBe(hashA);
  });

  it("fails closed when a publicJWT subject has no presented bearer token", async () => {
    bearerMocks.authenticateBearerWithTelemetry.mockResolvedValue({
      ok: true,
      environment: fakeEnv,
      subject: {
        type: "publicJWT",
        environmentId: fakeEnv.id,
        organizationId: fakeEnv.organizationId,
        projectId: fakeEnv.projectId,
      },
      ability: buildJwtAbility(["trigger:tasks:my-task"]),
      jwt: { oneTimeUse: true },
    });

    const req = new Request("https://api.trigger.dev/api/v1/tasks/my-task/trigger", {
      method: "POST",
    });
    expect(presentedBearerToken(req)).toBeUndefined();

    const res = await authenticateRequestForApiBuilder(req, { allowJWT: true });
    expect(res).toEqual({
      ok: false,
      status: 401,
      error: "Invalid or missing public JWT",
    });
  });

  it("keeps environment.apiKey for private API key subjects", async () => {
    bearerMocks.authenticateBearerWithTelemetry.mockResolvedValue({
      ok: true,
      environment: fakeEnv,
      subject: {
        type: "apiKey",
        keyId: "key_1",
        restricted: false,
        environmentId: fakeEnv.id,
        organizationId: fakeEnv.organizationId,
        projectId: fakeEnv.projectId,
      },
      ability: buildJwtAbility(["admin"]),
    });

    const req = new Request("https://api.trigger.dev/api/v1/tasks/my-task/trigger", {
      method: "POST",
      headers: { Authorization: "Bearer tr_sk_additional_key" },
    });
    const res = await authenticateRequestForApiBuilder(req, { allowJWT: true });
    expect(res.ok).toBe(true);
    if (!res.ok) throw new Error("unreachable");
    expect(res.authentication.type).toBe("PRIVATE");
    expect(res.authentication.apiKey).toBe(fakeEnv.apiKey);
  });
});
