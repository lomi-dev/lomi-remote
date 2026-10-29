//! `grid-patch-v1` is an experimental, typed state update, not terminal bytes.
//! Sparse updates retain changed cells and history append/trim operations. Geometry changes
//! use a bounded checkpoint; initial snapshots and the legacy Delta stay unchanged.
use super::*;
use serde::de::{SeqAccess, Visitor};
use std::{fmt, marker::PhantomData};

pub const GRID_PATCH_FORMAT: &str = "grid-patch-v1";

// Do not trust a wire array's advertised length or allocate it up front.
fn bounded<'de, D, T, const LIMIT: usize>(de: D) -> Result<Vec<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    struct List<T, const LIMIT: usize>(PhantomData<T>);
    impl<'de, T: Deserialize<'de>, const LIMIT: usize> Visitor<'de> for List<T, LIMIT> {
        type Value = Vec<T>;
        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            f.write_str("a bounded grid array")
        }
        fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
            let mut result = Vec::new();
            while let Some(item) = seq.next_element()? {
                if result.len() == LIMIT {
                    return Err(serde::de::Error::custom("grid array too large"));
                }
                result.push(item);
            }
            Ok(result)
        }
    }
    de.deserialize_seq(List::<T, LIMIT>(PhantomData))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields, try_from = "PatchWire")]
pub struct GridPatch {
    profile: String,
    version: u8,
    format: String,
    session_epoch: Uuid,
    previous_sequence: DecimalU64,
    sequence: DecimalU64,
    output_offset: DecimalU64,
    rows: usize,
    cols: usize,
    update: GridUpdate,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PatchWire {
    profile: String,
    version: u8,
    format: String,
    session_epoch: SessionEpoch,
    previous_sequence: DecimalU64,
    sequence: DecimalU64,
    output_offset: DecimalU64,
    rows: usize,
    cols: usize,
    update: GridUpdate,
}
impl TryFrom<PatchWire> for GridPatch {
    type Error = &'static str;
    fn try_from(w: PatchWire) -> Result<Self, Self::Error> {
        let patch = Self {
            profile: w.profile,
            version: w.version,
            format: w.format,
            session_epoch: Uuid::from_bytes(w.session_epoch.to_bytes()),
            previous_sequence: w.previous_sequence,
            sequence: w.sequence,
            output_offset: w.output_offset,
            rows: w.rows,
            cols: w.cols,
            update: w.update,
        };
        patch.validate()?;
        Ok(patch)
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase", deny_unknown_fields)]
pub enum GridUpdate {
    Sparse {
        metadata: Box<GridMetadata>,
        normal: Box<BufferPatch>,
        alternate: Box<BufferPatch>,
    },
    Checkpoint {
        state: Box<Snapshot>,
    },
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GridMetadata {
    active: String,
    modes: Modes,
    #[serde(deserialize_with = "required_option")]
    title: Option<String>,
    cursor_style: CursorStyle,
    #[serde(deserialize_with = "bounded::<_, _, 269>")]
    colors: Vec<Option<RgbColor>>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BufferPatch {
    base_y: usize,
    line_count: usize,
    previous_base_y: usize,
    previous_line_count: usize,
    retained_start: usize,
    retained_lines: usize,
    cursor: Cursor,
    saved_cursor: Cursor,
    #[serde(deserialize_with = "bounded::<_, _, 4352>")]
    rows: Vec<RowPatch>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RowPatch {
    index: usize,
    wrapped: bool,
    #[serde(deserialize_with = "bounded::<_, _, 512>")]
    cells: Vec<CellPatch>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CellPatch {
    index: usize,
    repeat: usize,
    cell: Cell,
}

fn encoded_size(value: &impl Serialize) -> Result<usize, &'static str> {
    struct Counter(usize);
    impl std::io::Write for Counter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0 = self.0.saturating_add(bytes.len());
            if self.0 > MAX_SNAPSHOT_BYTES {
                return Err(std::io::Error::other("grid patch too large"));
            }
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut counter = Counter(0);
    serde_json::to_writer(&mut counter, value).map_err(|_| "grid patch too large")?;
    Ok(counter.0)
}
// Find the longest old-grid run equal to a prefix of the new grid, allowing
// edited trailing rows after a scroll. KMP keeps
// repeated/blank scrollback linear in row comparisons rather than quadratic.
fn overlap(old: &[Row], new: &[Row]) -> usize {
    let mut prefix = vec![0; new.len()];
    for i in 1..new.len() {
        let mut j = prefix[i - 1];
        while j > 0 && new[i] != new[j] {
            j = prefix[j - 1];
        }
        if new[i] == new[j] {
            j += 1;
        }
        prefix[i] = j;
    }
    let mut matched = 0;
    let mut best = (0, 0);
    for (i, row) in old.iter().enumerate() {
        while matched > 0 && *row != new[matched] {
            matched = prefix[matched - 1];
        }
        if *row == new[matched] {
            matched += 1;
        }
        if matched > best.1 {
            best = (i + 1 - matched, matched);
        }
        if matched == new.len() && i + 1 < old.len() {
            matched = prefix[matched - 1];
        }
    }
    best.0
}
impl BufferPatch {
    fn between(old: &Buffer, new: &Buffer) -> Self {
        let cols = new.lines[0].cells.len();
        let cost = |start: usize| -> usize {
            new.lines
                .iter()
                .enumerate()
                .map(|(i, row)| {
                    old.lines.get(start + i).map_or(cols, |before| {
                        before
                            .cells
                            .iter()
                            .zip(&row.cells)
                            .filter(|(a, b)| a != b)
                            .count()
                    })
                })
                .sum()
        };
        let candidate = overlap(&old.lines, &new.lines);
        let retained_start = if cost(candidate) < cost(0) {
            candidate
        } else {
            0
        };
        let retained_lines = (old.lines.len() - retained_start).min(new.lines.len());
        let rows = new
            .lines
            .iter()
            .enumerate()
            .filter_map(|(index, after)| {
                let before = (index < retained_lines).then(|| &old.lines[retained_start + index]);
                if before == Some(after) {
                    return None;
                }
                let mut cells: Vec<CellPatch> = Vec::new();
                for (index, cell) in after.cells.iter().enumerate() {
                    if before.is_some_and(|row| &row.cells[index] == cell) {
                        continue;
                    }
                    if let Some(last) = cells.last_mut()
                        && last.index + last.repeat == index
                        && last.cell == *cell
                    {
                        last.repeat += 1;
                    } else {
                        cells.push(CellPatch {
                            index,
                            repeat: 1,
                            cell: cell.clone(),
                        });
                    }
                }
                Some(RowPatch {
                    index,
                    wrapped: after.wrapped,
                    cells,
                })
            })
            .collect();
        Self {
            base_y: new.base_y,
            line_count: new.lines.len(),
            previous_base_y: old.base_y,
            previous_line_count: old.lines.len(),
            retained_start,
            retained_lines,
            cursor: new.cursor.clone(),
            saved_cursor: new.saved_cursor.clone(),
            rows,
        }
    }
    fn validate(&self, rows: usize, cols: usize, alternate: bool) -> Result<(), &'static str> {
        if self.base_y > 4096
            || self.previous_base_y > 4096
            || (alternate && (self.base_y != 0 || self.previous_base_y != 0))
            || self.line_count != self.base_y + rows
            || self.previous_line_count != self.previous_base_y + rows
            || self
                .line_count
                .checked_mul(cols)
                .is_none_or(|n| n > MAX_CELLS)
            || self
                .previous_line_count
                .checked_mul(cols)
                .is_none_or(|n| n > MAX_CELLS)
            || self.retained_start > self.previous_line_count
            || self.retained_lines > self.previous_line_count - self.retained_start
            || self.retained_lines > self.line_count
            || self.cursor.x > cols
            || self.saved_cursor.x > cols
            || self.cursor.y >= rows
            || self.saved_cursor.y >= rows
        {
            return Err("invalid patch buffer geometry");
        }
        let mut previous = None;
        let mut next_appended = self.retained_lines;
        for row in &self.rows {
            if row.index >= self.line_count || previous.is_some_and(|i| i >= row.index) {
                return Err("invalid patch row index");
            }
            previous = Some(row.index);
            let appended = row.index >= self.retained_lines;
            if appended {
                if row.index != next_appended {
                    return Err("missing appended row");
                }
                next_appended += 1;
            }
            let mut end = 0;
            for c in &row.cells {
                if c.index < end
                    || c.repeat == 0
                    || c.index.checked_add(c.repeat).is_none_or(|end| end > cols)
                    || (appended && c.index != end)
                {
                    return Err("invalid patch cell range");
                }
                end = c.index + c.repeat;
                let c = &c.cell;
                if !valid_text(&c.text, 128)
                    || c.width > 2
                    || c.underline_style > 5
                    || c.hyperlink.as_ref().is_some_and(|h| !valid_hyperlink(h))
                    || c.flags.len() > 7
                    || c.flags.iter().enumerate().any(|(i, f)| {
                        ![
                            "bold", "dim", "italic", "inverse", "hidden", "strike", "blink",
                        ]
                        .contains(&f.as_str())
                            || c.flags[..i].contains(f)
                    })
                    || [&c.fg, &c.bg]
                        .into_iter()
                        .chain(c.underline_color.iter())
                        .any(|c| matches!(c,Color::Indexed{index} if *index>255))
                {
                    return Err("invalid patch cell");
                }
            }
            if appended && end != cols {
                return Err("incomplete appended row");
            }
        }
        if next_appended != self.line_count {
            return Err("missing appended rows");
        }
        Ok(())
    }
    fn validate_against(&self, buffer: &Buffer, cols: usize) -> Result<(), Error> {
        if self.previous_base_y != buffer.base_y || self.previous_line_count != buffer.lines.len() {
            return Err(Error::InvalidState);
        }
        // Validate the resulting wide-cell topology using borrowed cells, before
        // cloning or allocating a replacement grid.
        for row in &self.rows {
            let before = (row.index < self.retained_lines)
                .then(|| &buffer.lines[self.retained_start + row.index]);
            let cell = |index| -> &Cell {
                let end = row.cells.partition_point(|run| run.index <= index);
                if end > 0 {
                    let run = &row.cells[end - 1];
                    if index < run.index + run.repeat {
                        return &run.cell;
                    }
                }
                &before.expect("appended rows validated complete").cells[index]
            };
            for i in 0..cols {
                let c = cell(i);
                if (c.width == 0 && (!c.text.is_empty() || i == 0 || cell(i - 1).width != 2))
                    || (c.width == 2 && (i + 1 >= cols || cell(i + 1).width != 0))
                {
                    return Err(Error::InvalidState);
                }
            }
        }
        Ok(())
    }
    fn apply(&self, buffer: &mut Buffer, cols: usize) {
        buffer.lines.drain(..self.retained_start);
        buffer.lines.truncate(self.retained_lines);
        for row in &self.rows {
            if row.index >= self.retained_lines {
                let cells = row
                    .cells
                    .iter()
                    .flat_map(|run| std::iter::repeat_n(run.cell.clone(), run.repeat))
                    .collect();
                buffer.lines.push(Row {
                    wrapped: row.wrapped,
                    cells,
                });
            } else {
                buffer.lines[row.index].wrapped = row.wrapped;
                for run in &row.cells {
                    for cell in
                        &mut buffer.lines[row.index].cells[run.index..run.index + run.repeat]
                    {
                        *cell = run.cell.clone();
                    }
                }
            }
        }
        debug_assert!(buffer.lines.iter().all(|row| row.cells.len() == cols));
        buffer.base_y = self.base_y;
        buffer.cursor = self.cursor.clone();
        buffer.saved_cursor = self.saved_cursor.clone();
    }
}
// Serialize the prospective expanded state through borrowed cells. This must run
// before cloning a snapshot: a tiny repeat run can otherwise expand large text
// and hyperlink strings far beyond the 8 MiB state limit.
struct SnapshotView<'a> {
    baseline: &'a Snapshot,
    patch: &'a GridPatch,
    metadata: &'a GridMetadata,
    normal: &'a BufferPatch,
    alternate: &'a BufferPatch,
}
struct BufferView<'a> {
    baseline: &'a Buffer,
    patch: &'a BufferPatch,
    cols: usize,
}
struct RowsView<'a>(&'a BufferView<'a>);
struct RowView<'a> {
    baseline: Option<&'a Row>,
    patch: Option<&'a RowPatch>,
    cols: usize,
}
struct CellsView<'a>(&'a RowView<'a>);
fn projected_cell<'a>(
    patch: Option<&'a RowPatch>,
    baseline: Option<&'a Row>,
    index: usize,
) -> &'a Cell {
    if let Some(row) = patch {
        let end = row.cells.partition_point(|run| run.index <= index);
        if end > 0 {
            let run = &row.cells[end - 1];
            if index < run.index + run.repeat {
                return &run.cell;
            }
        }
    }
    &baseline
        .expect("validated appended rows cover every cell")
        .cells[index]
}
impl Serialize for SnapshotView<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut s = serializer.serialize_struct("Snapshot", 14)?;
        s.serialize_field("profile", &self.patch.profile)?;
        s.serialize_field("version", &self.patch.version)?;
        s.serialize_field("sessionEpoch", &self.patch.session_epoch)?;
        s.serialize_field("sequence", &self.patch.sequence)?;
        s.serialize_field("outputOffset", &self.patch.output_offset)?;
        s.serialize_field("rows", &self.baseline.rows)?;
        s.serialize_field("cols", &self.baseline.cols)?;
        s.serialize_field("active", &self.metadata.active)?;
        s.serialize_field(
            "normal",
            &BufferView {
                baseline: &self.baseline.normal,
                patch: self.normal,
                cols: self.baseline.cols,
            },
        )?;
        s.serialize_field(
            "alternate",
            &BufferView {
                baseline: &self.baseline.alternate,
                patch: self.alternate,
                cols: self.baseline.cols,
            },
        )?;
        s.serialize_field("modes", &self.metadata.modes)?;
        s.serialize_field("title", &self.metadata.title)?;
        s.serialize_field("cursorStyle", &self.metadata.cursor_style)?;
        s.serialize_field("colors", &self.metadata.colors)?;
        s.end()
    }
}
impl Serialize for BufferView<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut s = serializer.serialize_struct("Buffer", 4)?;
        s.serialize_field("lines", &RowsView(self))?;
        s.serialize_field("baseY", &self.patch.base_y)?;
        s.serialize_field("cursor", &self.patch.cursor)?;
        s.serialize_field("savedCursor", &self.patch.saved_cursor)?;
        s.end()
    }
}
impl Serialize for RowsView<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeSeq;
        let b = self.0;
        let mut s = serializer.serialize_seq(Some(b.patch.line_count))?;
        for index in 0..b.patch.line_count {
            let baseline = (index < b.patch.retained_lines)
                .then(|| &b.baseline.lines[b.patch.retained_start + index]);
            let patch = b
                .patch
                .rows
                .binary_search_by_key(&index, |row| row.index)
                .ok()
                .map(|i| &b.patch.rows[i]);
            s.serialize_element(&RowView {
                baseline,
                patch,
                cols: b.cols,
            })?;
        }
        s.end()
    }
}
impl Serialize for RowView<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let wrapped = self.patch.map_or_else(
            || self.baseline.expect("validated retained row").wrapped,
            |row| row.wrapped,
        );
        let mut s = serializer.serialize_struct("Row", 2)?;
        s.serialize_field("wrapped", &wrapped)?;
        s.serialize_field("cells", &CellsView(self))?;
        s.end()
    }
}
impl Serialize for CellsView<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeSeq;
        let row = self.0;
        let mut s = serializer.serialize_seq(Some(row.cols))?;
        for index in 0..row.cols {
            s.serialize_element(projected_cell(row.patch, row.baseline, index))?;
        }
        s.end()
    }
}
impl GridPatch {
    pub fn previous_sequence(&self) -> DecimalU64 {
        self.previous_sequence
    }
    pub fn sequence(&self) -> DecimalU64 {
        self.sequence
    }
    pub fn output_offset(&self) -> DecimalU64 {
        self.output_offset
    }
    pub fn session_epoch(&self) -> Uuid {
        self.session_epoch
    }
    pub fn from_json(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > MAX_SNAPSHOT_BYTES {
            return Err(Error::SnapshotTooLarge);
        }
        serde_json::from_slice(bytes).map_err(|_| Error::InvalidState)
    }
    pub fn between(old: &Snapshot, new: &Snapshot) -> Result<Self, Error> {
        old.validate().map_err(|_| Error::InvalidState)?;
        new.validate().map_err(|_| Error::InvalidState)?;
        encoded_size(old).map_err(|_| Error::SnapshotTooLarge)?;
        encoded_size(new).map_err(|_| Error::SnapshotTooLarge)?;
        if old.session_epoch != new.session_epoch
            || old.sequence.0.checked_add(1) != Some(new.sequence.0)
            || old.output_offset.0 > new.output_offset.0
        {
            return Err(Error::InvalidState);
        }
        let same_topology = old.rows == new.rows && old.cols == new.cols;
        let update = if same_topology {
            GridUpdate::Sparse {
                metadata: Box::new(GridMetadata {
                    active: new.active.clone(),
                    modes: new.modes.clone(),
                    title: new.title.clone(),
                    cursor_style: new.cursor_style.clone(),
                    colors: new.colors.clone(),
                }),
                normal: Box::new(BufferPatch::between(&old.normal, &new.normal)),
                alternate: Box::new(BufferPatch::between(&old.alternate, &new.alternate)),
            }
        } else {
            GridUpdate::Checkpoint {
                state: Box::new(new.clone()),
            }
        };
        let mut patch = Self {
            profile: PROFILE.into(),
            version: 1,
            format: GRID_PATCH_FORMAT.into(),
            session_epoch: new.session_epoch,
            previous_sequence: old.sequence,
            sequence: new.sequence,
            output_offset: new.output_offset,
            rows: old.rows,
            cols: old.cols,
            update,
        };
        // Pathological sparse updates fall back to a bounded checkpoint.
        if same_topology && encoded_size(&patch).is_err() {
            patch.update = GridUpdate::Checkpoint {
                state: Box::new(new.clone()),
            };
        }
        patch.validate().map_err(|_| Error::InvalidState)?;
        Ok(patch)
    }
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.profile != PROFILE
            || self.version != 1
            || self.format != GRID_PATCH_FORMAT
            || self.session_epoch.is_nil()
            || self.previous_sequence.0.checked_add(1) != Some(self.sequence.0)
        {
            return Err("invalid patch envelope");
        }
        TerminalState::check_size(self.rows, self.cols, 0)
            .map_err(|_| "invalid patch dimensions")?;
        match &self.update {
            GridUpdate::Checkpoint { state } => {
                state.validate()?;
                if state.session_epoch != self.session_epoch
                    || state.sequence != self.sequence
                    || state.output_offset != self.output_offset
                {
                    return Err("invalid checkpoint envelope");
                }
            }
            GridUpdate::Sparse {
                metadata,
                normal,
                alternate,
            } => {
                normal.validate(self.rows, self.cols, false)?;
                alternate.validate(self.rows, self.cols, true)?;
                TerminalState::check_size(self.rows, self.cols, normal.base_y)
                    .map_err(|_| "invalid patch dimensions")?;
                TerminalState::check_size(self.rows, self.cols, normal.previous_base_y)
                    .map_err(|_| "invalid previous patch dimensions")?;
                if !["normal", "alternate"].contains(&metadata.active.as_str())
                    || metadata.colors.len() != 269
                    || metadata.colors[259..].iter().any(Option::is_some)
                    || metadata
                        .title
                        .as_ref()
                        .is_some_and(|s| !valid_text(s, 4096))
                    || !["block", "underline", "bar"]
                        .contains(&metadata.cursor_style.shape.as_str())
                    || !["none", "x10", "vt200", "drag", "any"]
                        .contains(&metadata.modes.mouse_tracking.as_str())
                    || !["default", "utf8", "sgr"].contains(&metadata.modes.mouse_encoding.as_str())
                {
                    return Err("invalid patch metadata");
                }
            }
        }
        encoded_size(self)?;
        Ok(())
    }
    pub fn apply(&self, old: &Snapshot) -> Result<Snapshot, Error> {
        self.validate().map_err(|_| Error::InvalidState)?;
        old.validate().map_err(|_| Error::InvalidState)?;
        encoded_size(old).map_err(|_| Error::SnapshotTooLarge)?;
        if old.session_epoch != self.session_epoch
            || old.profile != self.profile
            || old.version != self.version
            || old.sequence != self.previous_sequence
            || old.output_offset.0 > self.output_offset.0
            || old.rows != self.rows
            || old.cols != self.cols
        {
            return Err(Error::InvalidState);
        }
        // Check topology before cloning/allocating a candidate grid.
        if let GridUpdate::Sparse {
            metadata,
            normal,
            alternate,
        } = &self.update
        {
            normal.validate_against(&old.normal, self.cols)?;
            alternate.validate_against(&old.alternate, self.cols)?;
            encoded_size(&SnapshotView {
                baseline: old,
                patch: self,
                metadata,
                normal,
                alternate,
            })
            .map_err(|_| Error::SnapshotTooLarge)?;
        }
        let next = match &self.update {
            GridUpdate::Checkpoint { state } => (**state).clone(),
            GridUpdate::Sparse {
                metadata,
                normal,
                alternate,
            } => {
                let mut next = old.clone();
                normal.apply(&mut next.normal, self.cols);
                alternate.apply(&mut next.alternate, self.cols);
                next.active = metadata.active.clone();
                next.modes = metadata.modes.clone();
                next.title = metadata.title.clone();
                next.cursor_style = metadata.cursor_style.clone();
                next.colors = metadata.colors.clone();
                next.sequence = self.sequence;
                next.output_offset = self.output_offset;
                next
            }
        };
        next.validate().map_err(|_| Error::InvalidState)?;
        encoded_size(&next).map_err(|_| Error::SnapshotTooLarge)?;
        Ok(next)
    }
}
