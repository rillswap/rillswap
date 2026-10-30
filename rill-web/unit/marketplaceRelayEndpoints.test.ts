import { expect, test } from "bun:test";

test("malformed signed endpoints do not veto a provider, and failover uses canonical permitted URLs", async () => {
  const child = Bun.spawn([process.execPath, "unit/fixtures/marketplaceRelayEndpointsFixture.ts"], { stdout: "pipe", stderr: "pipe" });
  const [output, errors, status] = await Promise.all([new Response(child.stdout).text(), new Response(child.stderr).text(), child.exited]);
  expect(errors).toBe(""); expect(status).toBe(0);
  expect(JSON.parse(output)).toEqual({ count: 1, alternatives: [["wss://allowed/"]] });
});
