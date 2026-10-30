import { test, expect } from "bun:test";
import { assertDisposableStack, assertRelayFaultStack } from "../regtest/stack";

test("Compose acceptance refuses the default or an unspecified project before issuing commands", () => {
  for (const COMPOSE_PROJECT_NAME of [undefined, "rillswap-dev", "other-project", "rill-reverse-browser-", "rill-reverse-browser-A"]) {
    expect(() => assertDisposableStack({ COMPOSE_PROJECT_NAME, RILL_DEV_WEB_PORT: "15273" })).toThrow("isolated");
  }
});

test("relay faults cannot target a retained UI development stack", () => {
  expect(() => assertRelayFaultStack({ COMPOSE_PROJECT_NAME: "rill-reverse-browser-ui-kept", RILL_DEV_WEB_PORT: "15273" })).toThrow("dedicated");
  expect(() => assertRelayFaultStack({ COMPOSE_PROJECT_NAME: "rill-reverse-browser-relays-new", RILL_DEV_WEB_PORT: "25273" })).not.toThrow();
});

test("Compose acceptance requires an explicit valid nondefault browser port", () => {
  for (const RILL_DEV_WEB_PORT of [undefined, "5273", "0", "0000", "05273", "1000", "99999", "abc"]) {
    expect(() => assertDisposableStack({ COMPOSE_PROJECT_NAME: "rill-reverse-browser-ci-123", RILL_DEV_WEB_PORT })).toThrow("nondefault");
  }
  expect(assertDisposableStack({ COMPOSE_PROJECT_NAME: "rill-reverse-browser-ci-123", RILL_DEV_WEB_PORT: "15273" })).toBe("rill-reverse-browser-ci-123");
});
