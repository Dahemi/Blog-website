const generateCode = require("../helper/gen_code");

describe("[V4] generateCode uses a secure, uniform RNG", () => {
  test("always returns the requested number of digits", () => {
    for (let i = 0; i < 1000; i++) {
      expect(generateCode(6)).toMatch(/^\d{6}$/);
    }
  });

  test("10,000 six-digit codes are effectively unique", () => {
    const seen = new Set();
    for (let i = 0; i < 10000; i++) seen.add(generateCode(6));
    expect(seen.size).toBeGreaterThan(9900);
  });

  test("digit distribution is uniform (chi-squared)", () => {
    const N = 60000; // 6 digits x 10,000 codes
    const counts = new Array(10).fill(0);
    for (let i = 0; i < 10000; i++) {
      for (const ch of generateCode(6)) counts[Number(ch)]++;
    }
    const expected = N / 10;
    const chi = counts.reduce(
      (s, o) => s + (o - expected) ** 2 / expected,
      0
    );
    expect(chi).toBeLessThan(27.88);
  });
});