// Generated from Rust JSON schema. Do not edit.

export type ConsumerAuthorizationId = string;
export type Capability =
  | "workspace.read"
  | "terminal.observe"
  | "terminal.control"
  | "terminal.manage"
  | "files.read"
  | "files.write"
  | "git.read"
  | "git.write"
  | "git.network"
  | "git.execute";
export type CapabilitySet = Capability[];
export type Effect = "none" | "committed" | "partial" | "unknown";
export type OperationId = string;
export type Method =
  | "workspace.get"
  | "workspace.capabilities"
  | "workspace.subscribe"
  | "terminal.create"
  | "terminal.split"
  | "terminal.rename"
  | "terminal.move"
  | "terminal.close"
  | "terminal.restart"
  | "terminal.attach"
  | "terminal.snapshot"
  | "terminal.ack"
  | "terminal.claim"
  | "terminal.renew"
  | "terminal.release"
  | "terminal.input"
  | "terminal.resize"
  | "files.list"
  | "files.stat"
  | "files.read"
  | "files.searchNames"
  | "files.watch"
  | "files.create"
  | "files.mkdir"
  | "files.rename"
  | "files.remove"
  | "git.repositories"
  | "git.status"
  | "git.diff"
  | "git.log"
  | "git.show"
  | "git.stage"
  | "git.unstage"
  | "git.commit"
  | "git.fetch"
  | "git.push"
  | "git.pull"
  | "operation.status"
  | "operation.cancel";
export type OperationParameterHash = string;
/**
 * Only identifiers/revisions, no names, paths, commands or cached plaintext.
 */
export type OperationResult =
  | {
      domainRevision: DecimalU64;
      kind: "domain";
    }
  | {
      domainRevision: DecimalU64;
      kind: "terminal";
      paneId: PaneId;
      sessionEpoch: SessionEpoch;
      sessionId: TerminalSessionId;
    }
  | {
      entryId: EntryId;
      fileRevision: FileRevision;
      kind: "file";
    }
  | {
      kind: "git";
      repoStateToken: RepoStateToken;
    };
export type DecimalU64 = string;
export type PaneId = string;
export type SessionEpoch = string;
export type TerminalSessionId = string;
export type EntryId = string;
export type FileRevision = string;
export type RepoStateToken = string;
export type OperationState = "accepted" | "running" | "succeeded" | "failed" | "cancelled" | "outcome_unknown";
export type WorkspaceId = string;

/**
 * Validated receipt DTO, not proof of persistence, admission, authority or fencing.
 * A consumer must authenticate current rights and row binding before disclosure.
 */
export interface OperationReceipt {
  actor: ConsumerAuthorizationId;
  actualRights: CapabilitySet;
  cancelRequested: boolean;
  effect: Effect;
  operationId: OperationId;
  originalMethod: Method;
  parameterHash: OperationParameterHash;
  repositoryExecution: boolean;
  result?: OperationResult | null;
  state: OperationState;
  workspaceId: WorkspaceId;
}
