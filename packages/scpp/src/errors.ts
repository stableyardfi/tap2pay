export type ScppErrorCode =
  | "SCPP_INVALID_FIELD"
  | "SCPP_UNKNOWN_FIELD"
  | "SCPP_MISSING_FIELD"
  | "SCPP_RESERVED_TAG"
  | "SCPP_TAG_OUT_OF_PROFILE"
  | "SCPP_LENGTH_OUT_OF_PROFILE"
  | "SCPP_MALFORMED_TLV"
  | "SCPP_INVALID_PUBLIC_KEY"
  | "SCPP_INVALID_CHALLENGE"
  | "SCPP_INVALID_SIGNATURE_ENCODING";

/* Every rejection carries a code rather than only a message: the reader maps a
   decline to a two-digit response code and an operator reads the code in a log,
   so the reason a message left the profile must survive both. */
export class ScppError extends Error {
  constructor(
    readonly code: ScppErrorCode,
    message: string,
    readonly field?: string,
  ) {
    super(message);
    this.name = "ScppError";
  }
}

export function invalidField(field: string, message: string): ScppError {
  return new ScppError("SCPP_INVALID_FIELD", `${field} ${message}`, field);
}
