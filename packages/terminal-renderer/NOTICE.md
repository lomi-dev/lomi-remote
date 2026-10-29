# Upstream internals provenance

The adapter was implemented against the source shipped in the pinned npm
packages `@xterm/xterm@6.0.0` and `@xterm/headless@6.0.0`. Package tarball URLs and
integrity digests are recorded in `package-lock.json`. Inspected primary source:

- `src/common/buffer/{Buffer,BufferSet,BufferLine,CellData,AttributeData,Constants}.ts`
- `src/common/services/{CoreService,CoreMouseService,OscLinkService,BufferService}.ts`
- `src/common/{Types,CircularList,InputHandler,CoreTerminal}.ts`
- `src/browser/{CoreBrowserTerminal,public/Terminal}.ts`
- `src/browser/services/ThemeService.ts`

In particular the custom UTF8 mouse encoder adapts the event-code semantics of
`CoreMouseService.ts`'s DEFAULT encoder. No upstream parser or renderer source
is vendored here. xterm remains an external, pinned dependency. The following
notice accompanies that adaptation:

Copyright (c) 2019 The xterm.js authors. All rights reserved.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
