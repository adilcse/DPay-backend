/**
 * Splits a load amount into note denominations (whole rupees). Port of `DenominationPlanner.kt`:
 * the bank issues notes for either the minimal plan or the change-heavy plan.
 *
 * Denominations are strictly limited to official Indian rupee notes:
 * ₹1, ₹2, ₹5, ₹10, ₹20, ₹50, ₹100, ₹200, ₹500, ₹1000.
 *
 * Every whole-rupee amount from ₹1 to the total can be paid exactly without gaps.
 */
export const STANDARD_RUPEES = [1000, 500, 200, 100, 50, 20, 10, 5, 2, 1] as const;

export const ALLOWED_DENOMINATIONS_PAISE = new Set<number>(STANDARD_RUPEES.map((r) => r * 100));

export const CHANGE_HEAVY_TARGET_COUNTS: readonly [number, number][] = [
  [1, 1],
  [2, 2],
  [5, 1],
  [10, 2],
  [20, 2],
  [50, 1],
  [100, 2],
  [200, 1],
  [500, 1],
  [1000, 1],
];

export function planMinimal(totalRupees: number): number[] {
  let remaining = totalRupees;
  let covered = 0;
  const notes: number[] = [];
  while (remaining > 0) {
    const note =
      STANDARD_RUPEES.find((d) => d <= remaining && d <= covered + 1) ??
      STANDARD_RUPEES.find((d) => d <= remaining)!;
    notes.push(note);
    covered += note;
    remaining -= note;
  }
  return notes;
}

export function planChangeHeavy(totalRupees: number): number[] {
  let remaining = totalRupees;
  let covered = 0;
  const notes: number[] = [];

  for (const [denomination, targetCount] of CHANGE_HEAVY_TARGET_COUNTS) {
    let count = 0;
    while (count < targetCount && remaining >= denomination && denomination <= covered + 1) {
      notes.push(denomination);
      covered += denomination;
      remaining -= denomination;
      count++;
    }
  }

  while (remaining > 0) {
    const note =
      STANDARD_RUPEES.find((d) => d <= remaining && d <= covered + 1) ??
      STANDARD_RUPEES.find((d) => d <= remaining)!;
    notes.push(note);
    covered += note;
    remaining -= note;
  }

  return notes;
}

/** Returns note values in paise, largest first. */
export function planDenominations(amountPaise: number, changeHeavy = false): number[] {
  if (!Number.isSafeInteger(amountPaise) || amountPaise <= 0) throw new RangeError('load amount must be positive');
  if (amountPaise % 100 !== 0) throw new RangeError('load amount must be whole rupees');
  const rupees = amountPaise / 100;
  const plan = changeHeavy ? planChangeHeavy(rupees) : planMinimal(rupees);
  return plan.map((n) => n * 100).sort((a, b) => b - a);
}

/** Validates if given values match either the minimal or change-heavy denomination plan and use standard notes. */
export function isValidDenominationPlan(values: readonly number[], totalPaise: number): boolean {
  if (!Number.isSafeInteger(totalPaise) || totalPaise <= 0 || totalPaise % 100 !== 0) return false;
  if (values.length === 0 || values.length > 100) return false;
  if (values.some((v) => !ALLOWED_DENOMINATIONS_PAISE.has(v))) return false;

  const minimal = planDenominations(totalPaise, false);
  const matchesMinimal = minimal.length === values.length && minimal.every((v, i) => v === values[i]);
  if (matchesMinimal) return true;

  const changeHeavy = planDenominations(totalPaise, true);
  return changeHeavy.length === values.length && changeHeavy.every((v, i) => v === values[i]);
}
