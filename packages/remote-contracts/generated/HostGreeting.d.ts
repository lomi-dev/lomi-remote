// Generated from Rust JSON schema. Do not edit.

/**
 * Externally tagged (postcard has no self-describing tags).
 */
export type HostGreeting =
  | {
      welcome: Welcome;
    }
  | {
      approvalPending: ApprovalPending;
    }
  | {
      staleEpoch: StaleEpoch;
    }
  | {
      updateRequired: UpdateRequired;
    }
  | {
      controlPending: ControlPending;
    };
export type OlderSide = "host" | "client";

/**
 * The directory itself goes on the `directory` stream; `directory` says whether it will follow.
 */
export interface Welcome {
  directory: boolean;
}
/**
 * `code` is the 6-digit confirmation code as a number (0..=999999, display zero-padded).
 */
export interface ApprovalPending {
  code: number;
  deadlineMs: number;
}
export interface StaleEpoch {
  authEpoch: number;
  hostAccessEpoch: number;
  runtimeGeneration: number;
}
export interface UpdateRequired {
  olderSide: OlderSide;
}
/**
 * The owner is asked on the Host to confirm control for this tunnel. `code` is the tunnel's
 * confirmation code; the device compares it with its own and shows its own copy.
 */
export interface ControlPending {
  code: number;
  deadlineMs: number;
}
