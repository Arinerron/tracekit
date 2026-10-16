use std::{collections::HashSet, hash::Hash, sync::Arc};

/// Deduplicates immutable shared values (command names, paths) so that thousands of
/// records share one allocation per distinct value.
#[derive(Debug)]
pub(crate) struct Interner<T: ?Sized + Eq + Hash>(HashSet<Arc<T>>);

impl<T: ?Sized + Eq + Hash> Default for Interner<T> {
    fn default() -> Self {
        Self(HashSet::new())
    }
}

impl<T: ?Sized + Eq + Hash> Interner<T> {
    /// The shared copy of `value`, allocated on first sight.
    pub(crate) fn intern(&mut self, value: &T) -> Arc<T>
    where
        for<'a> Arc<T>: From<&'a T>,
    {
        if let Some(shared) = self.0.get(value) {
            return Arc::clone(shared);
        }
        let shared = Arc::from(value);
        self.0.insert(Arc::clone(&shared));
        shared
    }

    /// Forgets values that no record references any more.
    pub(crate) fn prune(&mut self) {
        self.0.retain(|shared| Arc::strong_count(shared) > 1);
    }
}

#[cfg(test)]
mod tests {
    use std::{path::Path, sync::Arc};

    use super::Interner;

    #[test]
    fn shares_and_prunes() {
        let mut names = Interner::<str>::default();
        let a = names.intern("bash");
        let b = names.intern("bash");
        assert!(Arc::ptr_eq(&a, &b));
        drop((a, b));
        names.prune();
        let kept = names.intern("make");
        names.prune();
        assert!(Arc::ptr_eq(&kept, &names.intern("make")));
        assert_eq!(names.0.len(), 1, "unreferenced `bash` must be dropped");

        let mut paths = Interner::<Path>::default();
        assert!(Arc::ptr_eq(
            &paths.intern(Path::new("/a")),
            &paths.intern(Path::new("/a"))
        ));
    }
}
