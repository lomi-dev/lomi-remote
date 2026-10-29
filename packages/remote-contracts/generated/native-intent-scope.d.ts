// Generated from Rust JSON schema. Do not edit.

export type NativeIntentScope =
  | {
      scope: "workspace";
      workspaceId: WorkspaceId;
    }
  | {
      scope: "unscoped";
    };
export type WorkspaceId = string;
