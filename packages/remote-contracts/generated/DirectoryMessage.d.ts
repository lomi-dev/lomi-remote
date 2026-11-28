// Generated from Rust JSON schema. Do not edit.

export type DirectoryMessage =
  | {
      snapshot: DirectorySnapshot;
    }
  | {
      change: DirectoryUpdate;
    };
export type DisplayText = string;
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
  | "git.execute"
  | "chat.read"
  | "chat.send"
  | "chat.permissions.edit"
  | "chat.permissions.full";
/**
 * What this device may do there (ceiling of the workspace, limited by the device grant).
 */
export type CapabilitySet = Capability[];
export type ChatPermissions = "read-only" | "edit" | "full";
export type ChatModelId = string;
export type ChatProviderId = string;
export type DirectoryChatState = "Idle" | "Generating";
export type ChatThreadId = string;
export type ChatTitle = string;
export type DecimalU64 = string;
export type RuntimeId = string;
export type WorkspaceEpoch = string;
export type WorkspaceId = string;
export type DirectoryLayout =
  | {
      Pane: PaneId;
    }
  | {
      Split: {
        axis: SplitAxis;
        first: DirectoryLayout;
        second: DirectoryLayout;
      };
    };
export type PaneId = string;
export type SplitAxis = "horizontal" | "vertical";
export type TabId = string;
export type SessionEpoch = string;
export type PaneState = "starting" | "publishing" | "running" | "exited" | "stopped" | "lost";
export type DirectoryChange =
  | {
      workspace: DirectoryWorkspace;
    }
  | {
      removed: WorkspaceId;
    };

export interface DirectorySnapshot {
  host: DirectoryHost;
  seq: number;
  workspaces: DirectoryWorkspace[];
}
export interface DirectoryHost {
  name: DisplayText;
  platform: DisplayText;
  version: DisplayText;
}
export interface DirectoryWorkspace {
  capabilities: CapabilitySet;
  chats: DirectoryChat[];
  context: DirectoryContext;
  epoch: WorkspaceEpoch;
  id: WorkspaceId;
  name: DisplayText;
  tabs: DirectoryTab[];
  terminals: DirectoryTerminal[];
}
export interface DirectoryChat {
  /**
   * Unix milliseconds.
   */
  lastActivityAt: number;
  mode: ChatPermissions;
  model: ChatModelId;
  provider: ChatProviderId;
  state: DirectoryChatState;
  threadId: ChatThreadId;
  title: ChatTitle;
}
/**
 * The rest of the `WorkspaceContext` that rpc calls on this workspace carry (`id` and `epoch`
 * above are its `workspaceId` and `workspaceEpoch`). A change is sent as an update.
 */
export interface DirectoryContext {
  grantRevision: DecimalU64;
  hostAccessEpoch: DecimalU64;
  runtimeGeneration: DecimalU64;
  runtimeId: RuntimeId;
}
export interface DirectoryTab {
  layout: DirectoryLayout;
  name: DisplayText;
  tabId: TabId;
}
export interface DirectoryTerminal {
  paneId: PaneId;
  /**
   * `None` while the pane has no live session.
   */
  sessionEpoch?: SessionEpoch | null;
  state: PaneState;
  tabId: TabId;
  title: DisplayText;
}
export interface DirectoryUpdate {
  change: DirectoryChange;
  seq: number;
}
