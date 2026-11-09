//! Exact demand counters with no backing allocation for all-zero pages.

const PAGE_SLOTS: usize = 1024;

#[derive(Debug)]
struct Page {
    values: Box<[i64; PAGE_SLOTS]>,
    nonzero: usize,
}

#[derive(Debug, Default)]
pub(super) struct SparseDemand {
    pages: Vec<Option<Page>>,
}

impl SparseDemand {
    pub(super) fn get(&self, slot: u32) -> i64 {
        let slot = slot as usize;
        self.pages
            .get(slot / PAGE_SLOTS)
            .and_then(Option::as_ref)
            .map_or(0, |page| page.values[slot % PAGE_SLOTS])
    }

    pub(super) fn set(&mut self, slot: u32, value: i64) {
        if value == 0 && self.get(slot) == 0 {
            return;
        }
        let slot = slot as usize;
        let page_at = slot / PAGE_SLOTS;
        if self.pages.len() <= page_at {
            self.pages.resize_with(page_at + 1, || None);
        }
        let page = self.pages[page_at].get_or_insert_with(|| Page {
            values: Box::new([0; PAGE_SLOTS]),
            nonzero: 0,
        });
        let held = &mut page.values[slot % PAGE_SLOTS];
        page.nonzero -= usize::from(*held != 0);
        page.nonzero += usize::from(value != 0);
        *held = value;
        if page.nonzero == 0 {
            self.pages[page_at] = None;
        }
    }

    pub(super) fn heap_bytes(&self) -> usize {
        self.pages.capacity() * size_of::<Option<Page>>()
            + self.pages.iter().filter(|page| page.is_some()).count()
                * size_of::<[i64; PAGE_SLOTS]>()
    }
}

#[cfg(test)]
mod tests {
    use super::{PAGE_SLOTS, SparseDemand};

    #[test]
    fn zero_pages_are_absent_and_dense_values_remain_exact() {
        let mut demand = SparseDemand::default();
        demand.set(u32::MAX, 0);
        assert_eq!(demand.heap_bytes(), 0);
        for slot in 0..PAGE_SLOTS * 3 {
            demand.set(
                u32::try_from(slot).unwrap(),
                i64::MIN + i64::try_from(slot).unwrap(),
            );
        }
        for slot in 0..PAGE_SLOTS * 3 {
            assert_eq!(
                demand.get(u32::try_from(slot).unwrap()),
                i64::MIN + i64::try_from(slot).unwrap()
            );
        }
        for slot in 0..PAGE_SLOTS * 3 {
            demand.set(u32::try_from(slot).unwrap(), 0);
        }
        assert!(demand.pages.iter().all(Option::is_none));
        demand.set(u32::try_from(PAGE_SLOTS).unwrap(), i64::MAX);
        assert_eq!(demand.get(u32::try_from(PAGE_SLOTS).unwrap()), i64::MAX);
        assert_eq!(demand.get(u32::try_from(PAGE_SLOTS).unwrap() - 1), 0);
    }
}
