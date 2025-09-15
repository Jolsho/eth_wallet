use std::{collections::HashMap, 
    sync::{atomic::{AtomicUsize, Ordering}, Arc}, 
    time::Duration};

use tokio::{sync::RwLock, time::Instant};

pub trait Cacheable: Sized {
    type Item;
    fn new(item: Self::Item) -> Self;
}

pub struct CacheEntry<T: Cacheable> {
    pub expires: Duration,
    pub created_at: Instant,

    pub item: Arc<T>,
    pub next: Option<Arc<CacheEntry<T>>>,
    pub key: Arc<str>,
}

impl<T: Cacheable> CacheEntry<T> {
    pub fn new(expires: Duration, key: Arc<str>, item: T) -> Self {
        Self {
            item: Arc::new(item),
            expires,
            created_at: Instant::now(),
            next: None,
            key,
        }
    }

    pub fn is_expired(&self) -> bool {
        self.created_at.elapsed() >= self.expires
    }
}

pub struct Cache<T: Cacheable> {
    pub map: RwLock<HashMap<Arc<str>, Arc<CacheEntry<T>>>>,
    pub default_ttl: Duration,
    least_recently_used: RwLock<Option<Arc<CacheEntry<T>>>>,
    most_recently_used: RwLock<Option<Arc<CacheEntry<T>>>>,
    count: AtomicUsize,
    max: usize,
}

impl<T: Cacheable> Cache<T> {
    pub fn new(default_ttl: Duration, max: usize) -> Self {
        Self {
            map: RwLock::new(HashMap::new()),
            default_ttl,
            count: AtomicUsize::new(0),
            max: max,
            least_recently_used: RwLock::new(None),
            most_recently_used: RwLock::new(None),
        }
    }

    pub async fn exists(&self, key: &str) -> bool {
        self.map.read().await.contains_key(key)
    }

    pub async fn get(&self, key: &str) -> Option<Arc<T>> {
        let map = self.map.read().await;
        if let Some(e) = map.get(key) {
            if e.is_expired() {
                return None
            } else {
                return Some(e.item.clone())
            }
        } else {
            None
        }
    }

    pub async fn put(&self, key: &str, value: T::Item) {
        let mut map = self.map.write().await;
        let real_key: Arc<str> = Arc::from(key);
        let entry = Arc::new(CacheEntry::new(self.default_ttl, real_key.clone(), T::new(value)));
        map.insert(real_key, entry.clone());
        let mut val = self.most_recently_used.write().await;
        val.replace(entry.clone());

        let count = self.count.fetch_add(1, Ordering::SeqCst);

        if count >= self.max {
            self.cleanup_expired().await;
        }
    }

    pub async fn cleanup_expired(&self) {
        let mut current = self.least_recently_used.read().await.clone();
        loop {
            if self.count.load(Ordering::SeqCst) < self.max / 2 {
                break;
            }

            if let Some(entry) = current {
                if entry.is_expired() {
                    let mut map = self.map.write().await;
                    map.remove(&entry.key);
                    self.count.fetch_sub(1, Ordering::SeqCst);
                    current = entry.next.clone();
                } else {
                    current = entry.next.clone();
                }
            } else {
                break;
            }
        }
    }
}
