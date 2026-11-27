import { describe, expect, it } from "vitest";
import { dict, LANGS, LEVELS, levelName, otherLang, STATUS, statusName, t, TACTIC_ORDER, TACTICS, tacticName } from "../../src/i18n";

describe("i18n", () => {
  it("every UI string exists in both languages", () => {
    const zh = dict("zh"), en = dict("en");
    expect(Object.keys(zh)).toEqual(Object.keys(en));
    for (const k of Object.keys(zh)) {
      expect(zh[k], `zh.${k}`).toBeTruthy();
      // "untranslated" is a Chinese-only notice; every other English string must be filled
      if (k !== "untranslated") expect(en[k], `en.${k}`).toBeTruthy();
    }
  });

  it("tactic, level and status names exist in both languages", () => {
    for (const map of [TACTICS, LEVELS, STATUS]) for (const [k, v] of Object.entries(map)) for (const l of LANGS) expect(v[l], `${k}.${l}`).toBeTruthy();
  });

  it("tactic IDs follow ATT&CK's TA0000 format and are listed once", () => {
    for (const id of TACTIC_ORDER) expect(id).toMatch(/^TA\d{4}$/);
    expect(new Set(TACTIC_ORDER).size).toBe(TACTIC_ORDER.length);
  });

  it("level ranks sort critical first", () => {
    expect(Object.entries(LEVELS).sort((a, b) => a[1].rank - b[1].rank).map(([k]) => k)).toEqual(["critical", "high", "medium", "low", "informational"]);
  });

  it("lookup helpers translate and fall back to the raw value", () => {
    expect(t("en", "rules")).toBe("Detection Rules");
    expect(tacticName("zh", "TA0006")).toBe("凭据访问");
    expect(tacticName("en", "TA9999")).toBe("TA9999");
    expect(levelName("zh", "high")).toBe("高");
    expect(levelName("en", "weird")).toBe("weird");
    expect(statusName("en", "stable")).toBe("Stable");
    expect(otherLang("zh")).toBe("en");
    expect(otherLang("en")).toBe("zh");
  });
});
