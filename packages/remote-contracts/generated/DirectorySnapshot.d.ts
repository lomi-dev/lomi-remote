// Generated from Rust JSON schema. Do not edit.

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
