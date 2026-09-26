//! Debug-only heap accounting for the resolve path.
//!
//! [`Counting`] wraps a global allocator and keeps global live / peak /
//! total / count, plus per-[`Tag`] totals. With `mem-profile-tags` every
//! block carries a one-byte tag in a prefix header, so per-tag live bytes
//! and the per-tag composition at the global peak are exact (the header
//! itself is reported separately). Tags are set by [`scope`] (sync) and
//! [`tagged`] (per poll of a future); the innermost scope wins.

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum Tag {
    Other = 0,
    Source,
    Workspace,
    IndexHttp,
    IndexJson,
    IndexSummary,
    Query,
    Resolver,
    CrateDl,
    Unpack,
    Manifest,
    Features,
    Output,
    Vfs,
}

pub const TAG_COUNT: usize = 14;
pub const TAG_NAMES: [&str; TAG_COUNT] = [
    "other",
    "source",
    "workspace",
    "index_http",
    "index_json",
    "index_summary",
    "query",
    "resolver",
    "crate_dl",
    "unpack",
    "manifest",
    "features",
    "output",
    "vfs",
];

#[cfg(feature = "mem-profile")]
mod imp {
    use super::{TAG_COUNT, TAG_NAMES, Tag};
    use std::alloc::{GlobalAlloc, Layout};
    use std::fmt::Write;
    use std::sync::atomic::AtomicU8;
    use std::sync::atomic::AtomicU64;
    use std::sync::atomic::Ordering::Relaxed;

    pub(super) static CURRENT: AtomicU8 = AtomicU8::new(0);

    const HEADER: bool = cfg!(feature = "mem-profile-tags");

    #[allow(clippy::declare_interior_mutable_const)]
    const Z: AtomicU64 = AtomicU64::new(0);

    struct Stats {
        live: AtomicU64,
        peak: AtomicU64,
        total: AtomicU64,
        count: AtomicU64,
        live_blocks: AtomicU64,
        chunk_live: AtomicU64,
        chunk_peak: AtomicU64,
        header_live: AtomicU64,
        mem_at_peak: AtomicU64,
        window_peak: AtomicU64,
        tag_live: [AtomicU64; TAG_COUNT],
        tag_peak: [AtomicU64; TAG_COUNT],
        tag_total: [AtomicU64; TAG_COUNT],
        tag_count: [AtomicU64; TAG_COUNT],
        at_peak: [AtomicU64; TAG_COUNT],
        blocks_at_peak: AtomicU64,
    }

    static S: Stats = Stats {
        live: Z,
        peak: Z,
        total: Z,
        count: Z,
        live_blocks: Z,
        chunk_live: Z,
        chunk_peak: Z,
        header_live: Z,
        mem_at_peak: Z,
        window_peak: Z,
        tag_live: [Z; TAG_COUNT],
        tag_peak: [Z; TAG_COUNT],
        tag_total: [Z; TAG_COUNT],
        tag_count: [Z; TAG_COUNT],
        at_peak: [Z; TAG_COUNT],
        blocks_at_peak: Z,
    };

    pub fn memory_size() -> u64 {
        #[cfg(target_arch = "wasm32")]
        {
            (core::arch::wasm32::memory_size(0) as u64) * 65536
        }
        #[cfg(not(target_arch = "wasm32"))]
        {
            0
        }
    }

    /// dlmalloc's chunk size for a request (32-bit: 4-byte overhead,
    /// 8-byte alignment, 16-byte minimum chunk).
    fn chunk(req: usize) -> u64 {
        #[cfg(target_pointer_width = "32")]
        {
            if req < 12 {
                16
            } else {
                ((req + 4 + 7) & !7) as u64
            }
        }
        #[cfg(not(target_pointer_width = "32"))]
        {
            (((req + 8 + 15) & !15).max(32)) as u64
        }
    }

    fn header_len(layout: &Layout) -> usize {
        if HEADER { layout.align().max(8) } else { 0 }
    }

    fn on_alloc(tag: usize, size: usize, raw: usize, hdr: usize) {
        let size = size as u64;
        S.total.fetch_add(size, Relaxed);
        S.count.fetch_add(1, Relaxed);
        S.tag_total[tag].fetch_add(size, Relaxed);
        S.tag_count[tag].fetch_add(1, Relaxed);
        S.live_blocks.fetch_add(1, Relaxed);
        let c = S.chunk_live.fetch_add(chunk(raw), Relaxed) + chunk(raw);
        if c > S.chunk_peak.load(Relaxed) {
            S.chunk_peak.store(c, Relaxed);
        }
        S.header_live.fetch_add(hdr as u64, Relaxed);
        grow(tag, size);
    }

    fn grow(tag: usize, size: u64) {
        let live = S.live.fetch_add(size, Relaxed) + size;
        if live > S.window_peak.load(Relaxed) {
            S.window_peak.store(live, Relaxed);
        }
        if HEADER {
            let t = S.tag_live[tag].fetch_add(size, Relaxed) + size;
            if t > S.tag_peak[tag].load(Relaxed) {
                S.tag_peak[tag].store(t, Relaxed);
            }
        }
        if live > S.peak.load(Relaxed) {
            S.peak.store(live, Relaxed);
            S.mem_at_peak.store(memory_size(), Relaxed);
            S.blocks_at_peak.store(S.live_blocks.load(Relaxed), Relaxed);
            if HEADER {
                for i in 0..TAG_COUNT {
                    S.at_peak[i].store(S.tag_live[i].load(Relaxed), Relaxed);
                }
            }
        }
    }

    fn shrink(tag: usize, size: u64) {
        S.live.fetch_sub(size, Relaxed);
        if HEADER {
            S.tag_live[tag].fetch_sub(size, Relaxed);
        }
    }

    /// Counting wrapper around a global allocator.
    #[derive(Debug)]
    pub struct Counting<A>(pub A);

    unsafe impl<A: GlobalAlloc> GlobalAlloc for Counting<A> {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            unsafe { self.alloc_impl(layout, false) }
        }
        unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
            unsafe { self.alloc_impl(layout, true) }
        }
        unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
            let h = header_len(&layout);
            unsafe {
                let base = ptr.sub(h);
                let tag = if HEADER { *base as usize } else { 0 };
                let raw = layout.size() + h;
                shrink(tag, layout.size() as u64);
                S.live_blocks.fetch_sub(1, Relaxed);
                S.chunk_live.fetch_sub(chunk(raw), Relaxed);
                S.header_live.fetch_sub(h as u64, Relaxed);
                self.0
                    .dealloc(base, Layout::from_size_align_unchecked(raw, layout.align()));
            }
        }
        unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
            let h = header_len(&layout);
            unsafe {
                let base = ptr.sub(h);
                let old_raw = layout.size() + h;
                let new_raw = new_size + h;
                let out = self.0.realloc(
                    base,
                    Layout::from_size_align_unchecked(old_raw, layout.align()),
                    new_raw,
                );
                if out.is_null() {
                    return out;
                }
                let tag = if HEADER {
                    *out as usize
                } else {
                    CURRENT.load(Relaxed) as usize
                };
                let (old, new) = (layout.size() as u64, new_size as u64);
                S.total.fetch_add(new, Relaxed);
                S.count.fetch_add(1, Relaxed);
                S.tag_total[tag].fetch_add(new, Relaxed);
                S.tag_count[tag].fetch_add(1, Relaxed);
                S.chunk_live.fetch_sub(chunk(old_raw), Relaxed);
                let c = S.chunk_live.fetch_add(chunk(new_raw), Relaxed) + chunk(new_raw);
                if c > S.chunk_peak.load(Relaxed) {
                    S.chunk_peak.store(c, Relaxed);
                }
                if new >= old {
                    grow(tag, new - old);
                } else {
                    shrink(tag, old - new);
                }
                out.add(h)
            }
        }
    }

    impl<A: GlobalAlloc> Counting<A> {
        unsafe fn alloc_impl(&self, layout: Layout, zeroed: bool) -> *mut u8 {
            let h = header_len(&layout);
            let raw = layout.size() + h;
            unsafe {
                let l = Layout::from_size_align_unchecked(raw, layout.align());
                let base = if zeroed {
                    self.0.alloc_zeroed(l)
                } else {
                    self.0.alloc(l)
                };
                if base.is_null() {
                    return base;
                }
                let tag = CURRENT.load(Relaxed);
                if HEADER {
                    *base = tag;
                }
                on_alloc(tag as usize, layout.size(), raw, h);
                base.add(h)
            }
        }
    }

    /// Start a fresh accounting epoch: totals and counts zeroed, peaks
    /// re-based on what is live now.
    pub fn reset() {
        let live = S.live.load(Relaxed);
        S.total.store(0, Relaxed);
        S.count.store(0, Relaxed);
        S.peak.store(live, Relaxed);
        S.window_peak.store(live, Relaxed);
        S.chunk_peak.store(S.chunk_live.load(Relaxed), Relaxed);
        S.mem_at_peak.store(memory_size(), Relaxed);
        for i in 0..TAG_COUNT {
            S.tag_total[i].store(0, Relaxed);
            S.tag_count[i].store(0, Relaxed);
            let l = S.tag_live[i].load(Relaxed);
            S.tag_peak[i].store(l, Relaxed);
            S.at_peak[i].store(l, Relaxed);
        }
    }

    /// One-line JSON snapshot. `window_peak` is the peak live since the
    /// previous `snapshot` call, which then re-bases it.
    pub fn snapshot(label: &str) -> String {
        let prev = CURRENT.swap(0, Relaxed);
        let mut o = String::with_capacity(2048);
        let g = |a: &AtomicU64| a.load(Relaxed);
        let _ = write!(
            o,
            "{{\"label\":\"{label}\",\"header_mode\":{HEADER},\"memory_size\":{},\"live\":{},\"peak\":{},\"window_peak\":{},\"total\":{},\"count\":{},\"live_blocks\":{},\"chunk_live\":{},\"chunk_peak\":{},\"header_live\":{},\"mem_at_peak\":{},\"blocks_at_peak\":{},\"tags\":{{",
            memory_size(),
            g(&S.live),
            g(&S.peak),
            g(&S.window_peak),
            g(&S.total),
            g(&S.count),
            g(&S.live_blocks),
            g(&S.chunk_live),
            g(&S.chunk_peak),
            g(&S.header_live),
            g(&S.mem_at_peak),
            g(&S.blocks_at_peak),
        );
        for i in 0..TAG_COUNT {
            let _ = write!(
                o,
                "{}\"{}\":{{\"live\":{},\"peak\":{},\"at_peak\":{},\"total\":{},\"count\":{}}}",
                if i == 0 { "" } else { "," },
                TAG_NAMES[i],
                g(&S.tag_live[i]),
                g(&S.tag_peak[i]),
                g(&S.at_peak[i]),
                g(&S.tag_total[i]),
                g(&S.tag_count[i]),
            );
        }
        o.push_str("}}");
        S.window_peak.store(S.live.load(Relaxed), Relaxed);
        CURRENT.store(prev, Relaxed);
        let _ = Tag::Other;
        o
    }
}

#[cfg(feature = "mem-profile")]
pub use imp::{Counting, memory_size, reset, snapshot};

#[cfg(feature = "mem-profile")]
static MARKS: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());

/// Record a [`snapshot`] under `label` (no-op without `mem-profile`).
pub fn mark(label: &str) {
    #[cfg(feature = "mem-profile")]
    {
        let s = imp::snapshot(label);
        MARKS.lock().unwrap().push(s);
    }
    #[cfg(not(feature = "mem-profile"))]
    let _ = label;
}

/// Drain the recorded marks.
pub fn take_marks() -> Vec<String> {
    #[cfg(feature = "mem-profile")]
    {
        std::mem::take(&mut *MARKS.lock().unwrap())
    }
    #[cfg(not(feature = "mem-profile"))]
    {
        Vec::new()
    }
}

/// Restores the previous tag on drop.
#[derive(Debug)]
pub struct Scope {
    #[cfg(feature = "mem-profile")]
    prev: u8,
}

#[inline]
#[must_use]
pub fn scope(tag: Tag) -> Scope {
    #[cfg(feature = "mem-profile")]
    {
        Scope {
            prev: imp::CURRENT.swap(tag as u8, std::sync::atomic::Ordering::Relaxed),
        }
    }
    #[cfg(not(feature = "mem-profile"))]
    {
        let _ = tag;
        Scope {}
    }
}

impl Drop for Scope {
    #[inline]
    fn drop(&mut self) {
        #[cfg(feature = "mem-profile")]
        imp::CURRENT.store(self.prev, std::sync::atomic::Ordering::Relaxed);
    }
}

/// A future whose every poll runs under `tag`.
#[derive(Debug)]
pub struct Tagged<F> {
    tag: Tag,
    inner: F,
}

#[inline]
pub fn tagged<F: Future>(tag: Tag, inner: F) -> Tagged<F> {
    Tagged { tag, inner }
}

impl<F: Future> Future for Tagged<F> {
    type Output = F::Output;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<F::Output> {
        // SAFETY: `inner` is structurally pinned and never moved out.
        let this = unsafe { self.get_unchecked_mut() };
        let _g = scope(this.tag);
        unsafe { Pin::new_unchecked(&mut this.inner) }.poll(cx)
    }
}
