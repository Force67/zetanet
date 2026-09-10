// Copyright (C) 2023-2026 Vincent Hengel.
// For licensing information see LICENSE at the root of this distribution.
// Lock-free ordered hash map with epoch-based safe memory reclamation.
#pragma once
#include <mutex>

#include <bit>

#ifdef ZNET_USE_STL
#include <znet/z_stl_compat.h>
#else
#include <base/containers/vector.h>
#include <functional>
#include <utility>
#include <thread>
#endif

namespace base {

// Epoch-based reclamation. A node is freed only once every thread that could
// hold a pointer to it has exited its read-side critical section.
namespace ebr {

constexpr int kMaxSlots = 4096;

struct alignas(64) AnnounceSlot {
  std::atomic<long> epoch{-1};
};

struct EpochState {
  alignas(64) std::atomic<long> current{0};
  AnnounceSlot slots[kMaxSlots];

  // Thread ID pool; the mutex is only taken on thread birth/death.
  std::mutex pool_mutex;
  std::vector<int> free_ids;
  std::atomic<int> high_watermark{0};

  int acquire_id() {
    std::lock_guard<std::mutex> lk(pool_mutex);
    if (!free_ids.empty()) {
      int id = free_ids.back();
      free_ids.pop_back();
      return id;
    }
    int id = high_watermark.load(std::memory_order_relaxed);
    // Release: try_advance() must see this slot before the new thread announces.
    high_watermark.store(id + 1, std::memory_order_release);
    return id;
  }

  // Between the -1 store and the next announce, try_advance() may skip this
  // slot. Safe: the old thread left its critical section and the new one has
  // not entered one, so no reader holds a dangling pointer.
  void release_id(int id) {
    slots[id].epoch.store(-1, std::memory_order_release);
    std::lock_guard<std::mutex> lk(pool_mutex);
    free_ids.push_back(id);
  }

  int announce(int id) {
    while (true) {
      long e = current.load(std::memory_order_acquire);
      slots[id].epoch.exchange(e, std::memory_order_seq_cst);
      if (current.load(std::memory_order_acquire) == e) return id;
    }
  }

  void unannounce(int id) {
    slots[id].epoch.store(-1, std::memory_order_release);
  }

  void try_advance() {
    long e = current.load(std::memory_order_acquire);
    int n = high_watermark.load(std::memory_order_acquire);
    for (int i = 0; i < n; i++) {
      long a = slots[i].epoch.load(std::memory_order_acquire);
      if (a != -1 && a < e) return;
    }
    current.compare_exchange_strong(e, e + 1, std::memory_order_release,
                                    std::memory_order_relaxed);
  }

  long get_current() const { return current.load(std::memory_order_acquire); }
};

// Leaking singleton avoids destruction-order issues with thread_local.
inline EpochState& state() {
  static EpochState* s = new EpochState();
  return *s;
}

struct ThreadReg {
  int id;
  int nest_count = 0;
  ThreadReg() : id(state().acquire_id()) {}
  ~ThreadReg() { state().release_id(id); }
};

inline ThreadReg& thread_reg() {
  thread_local ThreadReg reg;
  return reg;
}

// RAII guard. Supports nesting; only the outermost scope announces.
struct Guard {
  struct inactive_t {};
  static constexpr inactive_t inactive{};

  bool active_;

  Guard() : active_(true) {
    auto& reg = thread_reg();
    if (reg.nest_count++ == 0) state().announce(reg.id);
  }
  explicit Guard(inactive_t) : active_(false) {}

  ~Guard() {
    if (active_) {
      auto& reg = thread_reg();
      if (--reg.nest_count == 0) state().unannounce(reg.id);
    }
  }

  Guard(Guard&& o) noexcept : active_(o.active_) { o.active_ = false; }
  Guard& operator=(Guard&& o) noexcept {
    if (this != &o) {
      if (active_) {
        auto& reg = thread_reg();
        if (--reg.nest_count == 0) state().unannounce(reg.id);
      }
      active_ = o.active_;
      o.active_ = false;
    }
    return *this;
  }
  Guard(const Guard&) = delete;
  Guard& operator=(const Guard&) = delete;
};

}  // namespace ebr

template <typename Key, typename Value>
class LockFreeOrderedHashMap {
 private:
  struct Node {
    ::std::pair<Key, Value> keyValue;
    base::Atomic<Node*> bucketNext;
    base::Atomic<Node*> orderNext;
    base::Atomic<bool> is_deleted;
    Node* staging_next;
    bool bucket_swept;
    bool order_swept;
    long retired_epoch;  // epoch when fully unlinked, -1 = live

    Node(const Key& k, Value&& v)
        : keyValue(::std::make_pair(k, ::std::move(v))),
          bucketNext(nullptr),
          orderNext(nullptr),
          is_deleted(false),
          staging_next(nullptr),
          bucket_swept{false},
          order_swept(false),
          retired_epoch(-1) {}

    Node(Key&& k, Value&& v)
        : keyValue(::std::make_pair(::std::move(k), ::std::move(v))),
          bucketNext(nullptr),
          orderNext(nullptr),
          is_deleted(false),
          staging_next(nullptr),
          bucket_swept{false},
          order_swept(false),
          retired_epoch(-1) {}
  };

  base::Atomic<Node*>* buckets;
  mem_size bucketCount;
  std::hash<Key> keyHasher;

  base::Atomic<Node*> orderHead;
  base::Atomic<Node*> orderTail;

  // Treiber stack of nodes not yet seen by the GC.
  base::Atomic<Node*> staging_head_{nullptr};

  // GC-owned state (only accessed under gc_mutex_).
  base::Mutex gc_mutex_;
  base::Vector<Node*> all_nodes_;

  // Shallowest live node for the key; tombstones stay linked until the GC
  // sweep, the sole unlinker, reclaims them.
  Node* find_in_bucket(const Key& key) const {
    mem_size index = hash_key(key);
    Node* curr = buckets[index].load(::std::memory_order_acquire);
    while (curr) {
      if (curr->keyValue.first == key &&
          !curr->is_deleted.load(::std::memory_order_acquire)) {
        return curr;
      }
      curr = curr->bucketNext.load(::std::memory_order_acquire);
    }
    return nullptr;
  }

  mem_size hash_key(const Key& key) const {
    // bucketCount is a power of two.
    return keyHasher(key) & (bucketCount - 1);
  }

  void stage_node(Node* node) {
    Node* old_head = staging_head_.load(::std::memory_order_relaxed);
    do {
      node->staging_next = old_head;
    } while (!staging_head_.compare_exchange_weak(
        old_head, node, ::std::memory_order_release,
        ::std::memory_order_relaxed));
  }

 public:
  // Iterators hold an ebr::Guard while alive. A long-lived iterator stalls
  // all GC; keep traversals short.

  template <typename IteratorType>
  class IteratorBase {
   protected:
    const LockFreeOrderedHashMap<Key, Value>* map;
    Node* currentNode;
    ebr::Guard guard_;

    void skip_deleted() {
      while (currentNode &&
             currentNode->is_deleted.load(::std::memory_order_acquire)) {
        static_cast<IteratorType*>(this)->advance_impl();
      }
    }

   public:
    using KeyValuePair = ::std::pair<Key, Value>;

    IteratorBase(const LockFreeOrderedHashMap<Key, Value>* m, Node* start_node)
        : map(m), currentNode(start_node), guard_() {
      skip_deleted();
    }

    IteratorBase(const LockFreeOrderedHashMap<Key, Value>* m)
        : map(m), currentNode(nullptr), guard_(ebr::Guard::inactive) {}

    KeyValuePair& operator*() const { return currentNode->keyValue; }
    KeyValuePair* operator->() const { return &currentNode->keyValue; }

    bool operator==(const IteratorBase& other) const {
      return currentNode == other.currentNode && map == other.map;
    }
    bool operator!=(const IteratorBase& other) const {
      return !(*this == other);
    }

    IteratorType& operator++() {
      if (currentNode) {
        static_cast<IteratorType*>(this)->advance_impl();
        skip_deleted();
      }
      return static_cast<IteratorType&>(*this);
    }
  };

  class OrderIterator : public IteratorBase<OrderIterator> {
    friend class IteratorBase<OrderIterator>;
    friend class LockFreeOrderedHashMap;

    void advance_impl() {
      if (this->currentNode)
        this->currentNode =
            this->currentNode->orderNext.load(::std::memory_order_acquire);
    }

   public:
    OrderIterator(const LockFreeOrderedHashMap<Key, Value>* m,
                  Node* start_node)
        : IteratorBase<OrderIterator>(m, start_node) {}
    OrderIterator(const LockFreeOrderedHashMap<Key, Value>* m)
        : IteratorBase<OrderIterator>(m) {}
  };

  class BucketIterator : public IteratorBase<BucketIterator> {
    friend class IteratorBase<BucketIterator>;
    friend class LockFreeOrderedHashMap;

   private:
    mem_size bucketIndex;

    void advance_impl() {
      if (!this->currentNode) return;
      this->currentNode =
          this->currentNode->bucketNext.load(::std::memory_order_acquire);
      while (!this->currentNode && bucketIndex < this->map->bucketCount - 1) {
        ++bucketIndex;
        this->currentNode =
            this->map->buckets[bucketIndex].load(::std::memory_order_acquire);
      }
      if (!this->currentNode) bucketIndex = this->map->bucketCount;
    }

   public:
    BucketIterator(const LockFreeOrderedHashMap<Key, Value>* m,
                   mem_size b_idx,
                   Node* start_node)
        : IteratorBase<BucketIterator>(m, start_node), bucketIndex(b_idx) {}
    BucketIterator(const LockFreeOrderedHashMap<Key, Value>* m)
        : IteratorBase<BucketIterator>(m), bucketIndex(m->bucketCount) {}

    bool operator==(const BucketIterator& other) const {
      return this->currentNode == other.currentNode &&
             bucketIndex == other.bucketIndex && this->map == other.map;
    }
    bool operator!=(const BucketIterator& other) const {
      return !(*this == other);
    }
  };

  OrderIterator order_begin() const {
    return OrderIterator(this,
                         orderHead.load(::std::memory_order_acquire));
  }
  OrderIterator order_end() const { return OrderIterator(this); }

  BucketIterator begin() const {
    for (mem_size i = 0; i < bucketCount; ++i) {
      Node* node = buckets[i].load(::std::memory_order_acquire);
      while (node && node->is_deleted.load(::std::memory_order_acquire))
        node = node->bucketNext.load(::std::memory_order_acquire);
      if (node) return BucketIterator(this, i, node);
    }
    return end();
  }
  BucketIterator end() const { return BucketIterator(this); }

  explicit LockFreeOrderedHashMap(mem_size count)
      : bucketCount(::std::bit_ceil(count > 0 ? count : mem_size{1})),
        orderHead(nullptr),
        orderTail(nullptr) {
    buckets = new base::Atomic<Node*>[bucketCount];
    for (mem_size i = 0; i < bucketCount; ++i)
      buckets[i].store(nullptr, ::std::memory_order_relaxed);
  }

  // Assumes no concurrent operations; frees staged and tracked nodes.
  ~LockFreeOrderedHashMap() {
    Node* staged = staging_head_.load(::std::memory_order_relaxed);
    while (staged) {
      Node* next = staged->staging_next;
      delete staged;
      staged = next;
    }
    for (Node* n : all_nodes_)
      delete n;
    delete[] buckets;
  }

  LockFreeOrderedHashMap(const LockFreeOrderedHashMap&) = delete;
  LockFreeOrderedHashMap& operator=(const LockFreeOrderedHashMap&) = delete;
  LockFreeOrderedHashMap(LockFreeOrderedHashMap&&) = delete;
  LockFreeOrderedHashMap& operator=(LockFreeOrderedHashMap&&) = delete;

  // NOTE: no rehash path; size the bucket count for peak occupancy.

  bool insert(const Key& key, Value&& value) {
    return insert_internal(key, ::std::move(value));
  }
  bool insert(Key&& key, Value&& value) {
    return insert_internal(::std::move(key), ::std::move(value));
  }

 private:
  template <typename K, typename V>
  bool insert_internal(K&& key, V&& value) {
    ebr::Guard guard;
    Node* newNode = nullptr;
    mem_size index = hash_key(key);

    while (true) {
      Node* existingNode = find_in_bucket(key);

      if (existingNode) {
        delete newNode;
        return false;
      }

      if (!newNode)
        newNode = new Node(::std::forward<K>(key), ::std::forward<V>(value));

      Node* oldHead = buckets[index].load(::std::memory_order_acquire);
      newNode->bucketNext.store(oldHead, ::std::memory_order_relaxed);

      if (buckets[index].compare_exchange_weak(
              oldHead, newNode, ::std::memory_order_release,
              ::std::memory_order_relaxed)) {
        // Post-CAS duplicate detection: the scan walks toward older nodes
        // only, so the first CAS winner for a key proceeds and every later
        // (shallower) duplicate backs off.
        Node* check =
            newNode->bucketNext.load(::std::memory_order_acquire);
        while (check) {
          if (check->keyValue.first == key &&
              !check->is_deleted.load(::std::memory_order_acquire)) {
            // Back off; the deeper node wins. Claim the node so a concurrent
            // remove() that saw it live stays balanced with our result.
            bool expected = false;
            const bool we_claimed = newNode->is_deleted.compare_exchange_strong(
                expected, true, ::std::memory_order_acq_rel,
                ::std::memory_order_acquire);
            newNode->order_swept = true;  // never entered order chain
            stage_node(newNode);
            delete_since_gc_.fetch_add(1, ::std::memory_order_relaxed);
            return !we_claimed;
          }
          check = check->bucketNext.load(::std::memory_order_acquire);
        }
        stage_node(newNode);
        break;
      }
    }

    // Phase 2: append to the insertion-order list (Michael & Scott).
    newNode->orderNext.store(nullptr, ::std::memory_order_relaxed);
    Node* expected_tail = nullptr;

    while (true) {
      Node* current_tail = orderTail.load(::std::memory_order_acquire);

      if (current_tail == nullptr) {
        if (orderHead.compare_exchange_weak(
                expected_tail, newNode, ::std::memory_order_release,
                ::std::memory_order_relaxed)) {
          orderTail.compare_exchange_strong(
              expected_tail, newNode, ::std::memory_order_release,
              ::std::memory_order_relaxed);
          return true;
        }
        expected_tail = nullptr;
        continue;
      }

      expected_tail = current_tail;
      Node* tail_next =
          current_tail->orderNext.load(::std::memory_order_acquire);

      if (orderTail.load(::std::memory_order_acquire) != current_tail)
        continue;

      if (tail_next != nullptr) {
        orderTail.compare_exchange_weak(
            current_tail, tail_next, ::std::memory_order_release,
            ::std::memory_order_relaxed);
        continue;
      }

      if (current_tail->orderNext.compare_exchange_weak(
              tail_next, newNode, ::std::memory_order_release,
              ::std::memory_order_relaxed)) {
        orderTail.compare_exchange_strong(
            current_tail, newNode, ::std::memory_order_release,
            ::std::memory_order_relaxed);
        return true;
      }
    }
  }

 public:
  bool find(const Key& key, Value& value) const {
    ebr::Guard guard;
    Node* node = find_in_bucket(key);
    if (node && !node->is_deleted.load(::std::memory_order_acquire)) {
      value = node->keyValue.second;
      return true;
    }
    return false;
  }

  template <typename Callback>
  bool with_value(const Key& key, Callback&& callback) const {
    ebr::Guard guard;
    Node* node = find_in_bucket(key);
    if (node && !node->is_deleted.load(::std::memory_order_acquire)) {
      callback(node->keyValue.second);
      return true;
    }
    return false;
  }

  // Drains the staging stack, sweeps both chains, stamps retirement epochs,
  // then frees nodes retired 2+ epochs ago.
  void collect_garbage() {
    std::lock_guard<base::Mutex> lock(gc_mutex_);
    collect_garbage_locked();
  }

  bool remove(const Key& key) {
    bool removed = remove_guarded(key);
    post_mutate();
    return removed;
  }

  base::Vector<Key> ordered_keys_snapshot() const {
    ebr::Guard guard;
    base::Vector<Key> keys;
    Node* curr = orderHead.load(::std::memory_order_acquire);
    while (curr) {
      if (!curr->is_deleted.load(::std::memory_order_acquire))
        keys.push_back(curr->keyValue.first);
      curr = curr->orderNext.load(::std::memory_order_acquire);
    }
    return keys;
  }

 private:
  static constexpr mem_size kAutoGCThreshold = 1024;
  base::Atomic<mem_size> delete_since_gc_{0};
  base::Atomic<mem_size> op_count_{0};

  bool remove_guarded(const Key& key) {
    ebr::Guard guard;
    while (true) {
      Node* node = find_in_bucket(key);
      if (!node) return false;

      bool expected = false;
      if (node->is_deleted.compare_exchange_weak(
              expected, true, ::std::memory_order_release,
              ::std::memory_order_relaxed)) {
        // Mark only; the GC sweep is the sole unlinker.
        delete_since_gc_.fetch_add(1, ::std::memory_order_relaxed);
        return true;
      }
      if (expected) return false;
    }
  }

  // Runs outside any EBR guard so retired nodes can actually be freed.
  void post_mutate() {
    mem_size n = op_count_.fetch_add(1, ::std::memory_order_relaxed);
    if ((n & 0xFF) == 0)
      ebr::state().try_advance();
    if (delete_since_gc_.load(::std::memory_order_relaxed) >=
        kAutoGCThreshold) {
      ::std::unique_lock<base::Mutex> lock(gc_mutex_, ::std::try_to_lock);
      if (lock.owns_lock())
        collect_garbage_locked();
    }
  }

  void collect_garbage_locked() {
    Node* staged =
        staging_head_.exchange(nullptr, ::std::memory_order_acquire);
    while (staged) {
      Node* next = staged->staging_next;
      all_nodes_.push_back(staged);
      staged = next;
    }
    delete_since_gc_.store(0, ::std::memory_order_relaxed);

    for (mem_size i = 0; i < bucketCount; ++i) {
      base::Atomic<Node*>* prev_ptr = &buckets[i];
      Node* curr = prev_ptr->load(::std::memory_order_acquire);
      while (curr) {
        Node* next = curr->bucketNext.load(::std::memory_order_acquire);
        if (curr->is_deleted.load(::std::memory_order_acquire)) {
          Node* expected = curr;
          if (prev_ptr->compare_exchange_strong(
                  expected, next, ::std::memory_order_release,
                  ::std::memory_order_relaxed)) {
            curr->bucket_swept = true;
            curr = next;
            continue;
          }
          prev_ptr = &buckets[i];
          curr = prev_ptr->load(::std::memory_order_acquire);
          continue;
        }
        prev_ptr = &curr->bucketNext;
        curr = next;
      }
    }

    Node* prev = nullptr;
    Node* curr = orderHead.load(::std::memory_order_acquire);
    while (curr) {
      Node* next = curr->orderNext.load(::std::memory_order_acquire);
      if (curr->is_deleted.load(::std::memory_order_acquire) &&
          next != nullptr) {
        Node* expected = curr;
        bool unlinked;
        if (prev) {
          unlinked = prev->orderNext.compare_exchange_strong(
              expected, next, ::std::memory_order_release,
              ::std::memory_order_relaxed);
        } else {
          unlinked = orderHead.compare_exchange_strong(
              expected, next, ::std::memory_order_release,
              ::std::memory_order_relaxed);
        }
        if (unlinked) {
          curr->order_swept = true;
        } else {
          if (prev)
            curr = prev->orderNext.load(::std::memory_order_acquire);
          else
            curr = orderHead.load(::std::memory_order_acquire);
          continue;
        }
      } else {
        prev = curr;
      }
      curr = next;
    }

    long current_e = ebr::state().get_current();
    for (mem_size i = 0; i < all_nodes_.size(); ++i) {
      Node* n = all_nodes_[i];
      if (n->bucket_swept &&
          n->order_swept && n->retired_epoch < 0)
        n->retired_epoch = current_e;
    }

    ebr::state().try_advance();

    // Free nodes retired 2+ epochs ago; no concurrent reader can reach them.
    long safe = ebr::state().get_current();
    mem_size write_idx = 0;
    for (mem_size i = 0; i < all_nodes_.size(); ++i) {
      if (all_nodes_[i]->retired_epoch >= 0 &&
          all_nodes_[i]->retired_epoch + 2 <= safe) {
        delete all_nodes_[i];
      } else {
        all_nodes_[write_idx++] = all_nodes_[i];
      }
    }
    all_nodes_.resize(write_idx);
  }
};

}  // namespace base
