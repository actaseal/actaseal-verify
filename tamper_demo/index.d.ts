export interface VerifyResult {
  verified: boolean;
  failures: string[];
}
export function canonicalDumps(value: unknown): string;
export function canonicalHash(value: unknown): Promise<string>;
export function verifyEvents(manifest: object, events: object[], failures: string[]): Promise<void>;
export function verifyReceipt(manifest: object, receipt: object, events: object[], failures: string[]): Promise<void>;
export function verifyPacket(manifest: object, receipt: object, events: object[]): Promise<VerifyResult>;
