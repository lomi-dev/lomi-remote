import assert from "node:assert/strict";
import { assertBuffer as compareBuffer } from "./projection.mjs";
export const assertBuffer = (t, source, name) => compareBuffer(t, source, name, assert);
