import { api } from "./api";
import {
  newProject,
  newSession,
  newTab,
  newId,
  layoutPanes,
  fileTabs,
  type Tab,
  type Session,
  type Layout,
  type FileTab,
  type Pane,
} from "./model";
import { loadedEditor, openEditorDocument } from "./editor-service";
import { EditorView } from "@codemirror/view";
import { undoDepth, redoDepth, undo, redo } from "@codemirror/commands";

declare global {
  interface Window {
    e0FixtureMode?: string;
    e0Workbench?: { get: () => Session | undefined; set: (s: Session) => void };
    e0Command?: (command: any) => Promise<unknown>;
    e0Result?: unknown;
  }
}
const wait = async (test: () => unknown) => {
  for (let i = 0; i < 200; i++) {
    if (test()) return;
    await new Promise((r) => setTimeout(r, 50));
  }
  throw Error("Fixture renderer deadline");
};
let revision = 0;
let file: FileTab;
let terminals = new Map<string, Pane>();
const hash = async (text: string) =>
  [
    ...new Uint8Array(
      await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text)),
    ),
  ]
    .map((x) => x.toString(16).padStart(2, "0"))
    .join("");
async function inspect() {
  const doc = loadedEditor(file)!;
  const content = document.querySelector(".cm-content") as HTMLElement;
  const view = content && EditorView.findFromDOM(content);
  const buffer = doc.readAgentBuffer({
    workspaceId: "fixture",
    panelId: file.id,
    relativePath: file.relative,
    maxChars: 1024,
  });
  return {
    documentId: doc.documentId,
    dirty: doc.dirty,
    textHash: await hash(doc.state.doc.toString()),
    selection: doc.state.selection.toJSON(),
    undo: undoDepth(doc.state),
    redo: redoDepth(doc.state),
    bufferRevision: buffer.text.bufferRevision,
    diskRevision: buffer.text.diskRevision,
    privateId: file.id,
    editorMounted: !!view,
    revision,
  };
}
export async function start(mode: string) {
  if (mode === "observer") {
    document.getElementById("root")!.textContent =
      "E0 read-only host projection";
    window.e0Command = async (command) => {
      if (command.op === "production-denied") {
        try { await api("load_session"); return false; } catch { return true; }
      }
      const s = await api("e0_desktop_projection");
      document.getElementById("root")!.textContent = JSON.stringify(s);
      return s;
    };
    return;
  }
  window.e0Command = async (command) => {
    await wait(() => window.e0Workbench);
    const bench = window.e0Workbench!;
    if (command.op === "initialize") {
      const project = newProject(command.root, "local:zsh");
      const workspace = project.workspaces[0];
      const a = newTab(command.root, "local:zsh", "Fixture A", 2);
      workspace.tabs = [a];
      const b = newTab(command.root, "local:zsh", "Fixture B");
      file = {
        type: "file",
        id: newId(),
        title: "private.txt",
        root: command.root,
        relative: "private.txt",
      };
      terminals = new Map(
        [...layoutPanes(a.layout), ...layoutPanes(b.layout)]
          .filter((p): p is Pane => p.type === "terminal")
          .map((p) => [p.id, p]),
      );
      a.layout = {
        type: "split",
        id: newId(),
        axis: "horizontal",
        ratio: 0.5,
        first: a.layout,
        second: file,
      };
      a.activePaneId = file.id;
      workspace.tabs.push(b);
      workspace.activeTabId = a.id;
      bench.set({
        ...newSession(),
        projects: [project],
        activeProjectId: project.id,
      });
      await wait(() => document.querySelector(".cm-content"));
      await openEditorDocument(file);
      const keepDisabled = [...document.querySelectorAll("button")].find(button => button.textContent?.trim() === "Keep disabled");
      keepDisabled?.click();
      await wait(() => ![...document.querySelectorAll("button")].some(button => button.textContent?.trim() === "Keep disabled"));
      return {
        tabA: a.id,
        tabB: b.id,
        paneA: [...terminals.keys()][0],
        paneB: [...terminals.keys()][2],
        paneC: [...terminals.keys()][1],
        ...(await inspect()),
      };
    }
    if (command.op === "edit") {
      const content = document.querySelector(".cm-content") as HTMLElement;
      content.focus();
      // WebKit editing enters through the browser's input/CodeMirror path.
      const line = content.querySelector(".cm-line")!;
      const text = line.firstChild!;
      const selection = window.getSelection()!;
      const range = document.createRange();
      range.selectNodeContents(line);
      range.collapse(false);
      selection.removeAllRanges();
      selection.addRange(range);
      content.dispatchEvent(new InputEvent("beforeinput", { bubbles: true, inputType: "insertText", data: "fixture dirty Ω" }));
      text.textContent = (text.textContent ?? "") + "fixture dirty Ω";
      range.selectNodeContents(line);
      range.collapse(false);
      selection.removeAllRanges();
      selection.addRange(range);
      content.dispatchEvent(new InputEvent("input", { bubbles: true, inputType: "insertText", data: "fixture dirty Ω" }));
      await wait(() => loadedEditor(file)?.dirty);
      EditorView.findFromDOM(content)!.dispatch({selection: {anchor: 2, head: 7}});
      return { inputPath: "native-webview-dom-input-codemirror-observer", ...(await inspect()) };
    }
    if (command.op === "history") {
      const view = EditorView.findFromDOM(
        document.querySelector(".cm-content")!,
      )!;
      const before = await inspect();
      if (!undo(view)) throw Error("Undo unavailable");
      const undone = await inspect();
      if (!redo(view)) throw Error("Redo unavailable");
      return { before, undone, redone: await inspect() };
    }
    if (command.op === "apply") {
      const snapshot = command.snapshot;
      if (snapshot.revision <= revision) throw Error("STALE_HOST_REVISION");
      const previous = bench.get()!;
      const next = structuredClone(previous);
      const ws = next.projects[0].workspaces[0];
      function privateTree(layout: Layout): Layout | null {
        if (layout.type !== "split")
          return layout.type === "terminal" ? null : layout;
        const a = privateTree(layout.first),
          b = privateTree(layout.second);
        return a && b ? { ...layout, first: a, second: b } : (a ?? b);
      }
      function hostTree(t: any): Layout {
        if (t.type === "terminal") {
          const pane = terminals.get(t.id);
          if (!pane) throw Error("UNKNOWN_HOST_TERMINAL");
          return pane;
        }
        return {
          type: "split",
          id: newId(),
          axis: "horizontal",
          ratio: 0.5,
          first: hostTree(t.first),
          second: hostTree(t.second),
        };
      }
      ws.tabs = ws.tabs.flatMap<Tab>((tab) => {
        if (tab.type !== "terminal") return [tab];
        const priv = privateTree(tab.layout);
        const host = snapshot.tabs.find((t: any) => t.id === tab.id);
        const shared = host ? hostTree(host.tree) : null;
        const layout =
          priv && shared
            ? {
                type: "split" as const,
                id: newId(),
                axis: "horizontal" as const,
                ratio: 0.5,
                first: shared,
                second: priv,
              }
            : (priv ?? shared);
        return layout
          ? [
              {
                ...tab,
                layout,
                activePaneId: layoutPanes(layout).some(
                  (p) => p.id === tab.activePaneId,
                )
                  ? tab.activePaneId
                  : layoutPanes(layout)[0].id,
              },
            ]
          : [];
      });
      // Retention occurs synchronously inside the actual Workbench setter.
      // The negative control replaces the actual setter for this operation.
      const setter = bench.set;
      if (command.noopSetter) bench.set = () => {};
      try { bench.set(next); } finally { bench.set = setter; }
      await new Promise((r) => setTimeout(r, 150));
      const committed = bench.get()!;
      const committedWs = committed.projects[0].workspaces[0];
      const membership = (tabs: Tab[]) => tabs.flatMap(t => t.type === "terminal"
        ? layoutPanes(t.layout).filter(p => p.type === "terminal").map(p => [p.id, t.id]) : [])
        .sort((a, b) => a[0].localeCompare(b[0]));
      const hostMembership = snapshot.tabs.flatMap((t: any) => {
        const leaves = (tree: any): string[] => tree.type === "terminal"
          ? [tree.id] : [...leaves(tree.first), ...leaves(tree.second)];
        return leaves(t.tree).map(id => [id, t.id]);
      }).sort((a: string[], b: string[]) => a[0].localeCompare(b[0]));
      if (JSON.stringify(membership(committedWs.tabs)) !== JSON.stringify(hostMembership))
        throw Error("WORKBENCH_COMMIT_MEMBERSHIP_MISMATCH");
      if (JSON.stringify(fileTabs(committed).map(t => t.id).sort()) !==
          JSON.stringify(fileTabs(previous).map(t => t.id).sort()))
        throw Error("WORKBENCH_PRIVATE_MEMBERSHIP_MISMATCH");
      // Only the selected tab renders. Visit each committed tab and compare the
      // actual Dockview descendants (including geometry), then restore selection.
      const renderedLayouts = [];
      const paneElements = () => [...document.querySelectorAll<HTMLElement>(
        ".terminal-layout [data-pane-id], .terminal-layout [data-file-pane-id]")];
      for (const tab of committedWs.tabs) {
        if (tab.type !== "terminal") continue;
        const navigation = structuredClone(bench.get()!);
        navigation.projects[0].workspaces[0].activeTabId = tab.id;
        bench.set(navigation);
        const expected = layoutPanes(tab.layout).map(p => p.id).sort();
        await wait(() => JSON.stringify(paneElements().map(p =>
          p.dataset.paneId ?? p.dataset.filePaneId).sort()) === JSON.stringify(expected));
        await wait(() => paneElements().every(p => {
          const r = p.getBoundingClientRect(); return r.width > 0 && r.height > 0;
        }));
        const rects = paneElements().map(p => p.getBoundingClientRect());
        for (let i = 0; i < rects.length; i++) for (let j = i + 1; j < rects.length; j++) {
          const a = rects[i], b = rects[j];
          if (Math.min(a.right, b.right) - Math.max(a.left, b.left) > 1 &&
              Math.min(a.bottom, b.bottom) - Math.max(a.top, b.top) > 1)
            throw Error("RENDERED_PANES_OVERLAP");
        }
        renderedLayouts.push({ tabId: tab.id, paneIds: expected });
      }
      const restore = structuredClone(bench.get()!);
      restore.projects[0].workspaces[0].activeTabId = committedWs.activeTabId;
      bench.set(restore);
      await wait(() => document.querySelector(".cm-content"));
      revision = snapshot.revision;
      const actual = bench.get()!;
      return {
        ...(await inspect()), renderedLayouts, terminalMembership: membership(actual.projects[0].workspaces[0].tabs),
        privateIds: fileTabs(actual).map(t => t.id),
        terminalIds: membership(actual.projects[0].workspaces[0].tabs).map(([id]) => id),
      };
    }
    if (command.op === "inspect") return inspect();
    throw Error("Unsupported fixture operation");
  };
}
