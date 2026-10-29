// Shared headless/browser cell oracle; no terminal parser or Node dependency.
export function assertBuffer(t, source, name, assert) {
  const actual = t._core._bufferService.buffers[name];
  assert.equal(actual.lines.length, source.lines.length);
  assert.equal(actual.ybase, source.baseY);
  assert.deepEqual({ x: actual.x, y: actual.y }, source.cursor);
  assert.deepEqual({ x: actual.savedX, y: actual.savedY }, source.savedCursor);
  source.lines.forEach((row, y) => {
    const target = actual.lines.get(y);
    assert.equal(target.isWrapped, row.wrapped);
    row.cells.forEach((cell, x) => {
      const projected = target.loadCell(x, actual.getNullCell());
      assert.equal(projected.getChars(), cell.text);
      assert.equal(projected.getWidth(), cell.width);
      for (const [flag, getter] of Object.entries({
        bold: "isBold",
        dim: "isDim",
        italic: "isItalic",
        inverse: "isInverse",
        hidden: "isInvisible",
        strike: "isStrikethrough",
        blink: "isBlink",
      }))
        assert.equal(!!projected[getter](), cell.flags.includes(flag), `${name} ${y}:${x} ${flag}`);
      for (const [channel, spec] of [
        ["Fg", cell.fg],
        ["Bg", cell.bg],
      ]) {
        assert.equal(!!projected[`is${channel}Default`](), spec.kind === "default");
        assert.equal(!!projected[`is${channel}RGB`](), spec.kind === "rgb");
        const expected = spec.kind === "default"
          ? -1
          : spec.kind === "indexed"
            ? spec.index
            : (spec.r << 16) | (spec.g << 8) | spec.b;
        assert.equal(projected[`get${channel}Color`](), expected);
      }
      const ext = target._extendedAttrs[x];
      assert.equal(ext ? (ext._ext & 0x1c000000) >>> 26 : 0, cell.underlineStyle);
      const underline = cell.underlineColor;
      const underlineBits = !underline || underline.kind === "default"
        ? 0
        : underline.kind === "indexed"
          ? 0x2000000 | underline.index
          : 0x3000000 |
            (underline.r << 16) |
            (underline.g << 8) |
            underline.b;
      assert.equal(ext?.underlineColor ?? 0, underlineBits);
      assert.deepEqual(ext?.urlId ? t._core._oscLinkService.getLinkData(ext.urlId) : null, cell.hyperlink);
    });
  });
}
