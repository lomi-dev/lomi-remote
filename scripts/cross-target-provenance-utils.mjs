export function assertInventories(label, source, copy, mobileOnly = []) {
  const sourcePaths = Object.keys(source).sort();
  const copyPaths = Object.keys(copy).sort();
  const expectedCopy = [...sourcePaths, ...mobileOnly].sort();
  if (JSON.stringify(copyPaths) !== JSON.stringify(expectedCopy)) {
    const sourceSet = new Set(sourcePaths);
    const copySet = new Set(copyPaths);
    const missing = sourcePaths.filter(path => !copySet.has(path));
    const added = copyPaths.filter(path => !sourceSet.has(path));
    throw new Error(`${label} inventory mismatch (missing=${missing.join(',')}; added=${added.join(',')})`);
  }
}

export function assertAdapted(label, source, copy, exceptions, mobileOnly = []) {
  assertInventories(label, source, copy, mobileOnly);
  const actualDiffs = Object.keys(source).filter(path => source[path] !== copy[path]).sort();
  const expected = [...exceptions].sort();
  if (JSON.stringify(actualDiffs) !== JSON.stringify(expected)) {
    throw new Error(`${label} differs outside its pinned adaptations: ${actualDiffs.join(', ') || '(none)'}`);
  }
}
