/**
 * Splits a load amount into note denominations (whole rupees). Port of `DenominationPlanner.kt`:
 * the bank only issues notes for exactly this plan.
 *
 * Every whole-rupee amount from ₹1 to the total can be paid exactly (₹5,000 → 15 notes).
 * Each new note is at most `covered + 1`; the final remainder becomes one note of whatever is left.
 */
const STANDARD_RUPEES = [2000, 1000, 500, 200, 100, 50, 20, 10, 5, 2, 1];

/** Returns note values in paise, largest first. */
export function planDenominations(amountPaise: number): number[] {
  if (!Number.isSafeInteger(amountPaise) || amountPaise <= 0) throw new RangeError('load amount must be positive');
  if (amountPaise % 100 !== 0) throw new RangeError('load amount must be whole rupees');
  let remaining = amountPaise / 100;
  let covered = 0;
  const notes: number[] = [];
  while (remaining > 0) {
    const note = remaining <= covered + 1 ? remaining : STANDARD_RUPEES.find((d) => d <= covered + 1)!;
    notes.push(note);
    covered += note;
    remaining -= note;
  }
  return notes.map((n) => n * 100).sort((a, b) => b - a);
}
