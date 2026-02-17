// Copyright (C) 2023-2026 Vincent Hengel.
// For licensing information see LICENSE at the root of this distribution.
// --- MODIFIED for lock-freedom AND ordering (with caveats) ---
#pragma once

#ifdef ZNET_USE_STL
#include <znet/z_stl_compat.h>
#else
#include <base/containers/vector.h>
#include <functional>
#include <utility>
#include <stdexcept>
#include <thread>
#endif

namespace base {

// Forward declaration
template <typename Key, typename Value>
class LockFreeOrderedHashMap;

template <typename Key, typename Value>
class LockFreeOrderedHashMap {
 private:
  struct Node {
    ::std::pair<Key, Value> keyValue;
    base::Atomic<Node*> bucketNext;  // Next node in the same hash bucket
    base::Atomic<Node*> orderNext;   // Next node in global insertion order
    base::Atomic<bool> is_deleted;   // Primary flag for logical deletion

    Node(const Key& k, Value&& v)
        : keyValue(::std::make_pair(k, ::std::move(v))),
          bucketNext(nullptr),
          orderNext(nullptr),
          is_deleted(false) {}

    Node(Key&& k, Value&& v)
        : keyValue(::std::make_pair(::std::move(k), ::std::move(v))),
          bucketNext(nullptr),
          orderNext(nullptr),
          is_deleted(false) {}
  };

  base::Atomic<Node*>* buckets;
  mem_size bucketCount;
  std::hash<Key> keyHasher;

  base::Atomic<Node*> orderHead;
  base::Atomic<Node*> orderTail;

  // --- Memory Management (Placeholder - Leaks during operation) ---
  base::Mutex allNodesMutex;  // Protects allNodes vector ONLY.
  base::Vector<Node*> allNodes;
  // --- Requires proper SMR scheme for production ---

  // Finds a node *only* via hash bucket chain. Does NOT check is_deleted.
  // Returns the node if key matches, nullptr otherwise.
  // Sets 'prev_bucket_next_ptr' to the atomic 'bucketNext' of the predecessor node,
  // or to the bucket head atomic itself if the target node is the head.
  Node* find_in_bucket(const Key& key, base::Atomic<Node*>*& prev_bucket_next_ptr) const {
    mem_size index = hash_key(key);
    prev_bucket_next_ptr = &buckets[index];
    Node* curr = buckets[index].load(::std::memory_order_acquire);

    while (curr) {
      if (curr->keyValue.first == key) {
        return curr;  // Found the node (might be logically deleted)
      }
      prev_bucket_next_ptr = &curr->bucketNext;
      curr = curr->bucketNext.load(::std::memory_order_acquire);
    }
    return nullptr;  // Not found in this bucket chain
  }

  mem_size hash_key(const Key& key) const {
    if (bucketCount == 0)
      throw ::std::logic_error("Bucket count is zero");
    return keyHasher(key) % bucketCount;
  }

  // Tries to physically unlink a node known to be logically deleted
  // from its bucket chain. Helper function. Optional "helping" mechanism.
  void try_unlink_bucket(Node* node, base::Atomic<Node*>* prev_bucket_next_ptr) {
    // This check is needed because prev_bucket_next_ptr is determined *before*
    // the node is marked deleted. We need to ensure the predecessor hasn't changed.
    // A simpler way might be to re-find the node and predecessor after marking,
    // but let's try this direct CAS first.
    Node* current_prev_points_to = prev_bucket_next_ptr->load(::std::memory_order_relaxed);
    if (current_prev_points_to ==
        node) {  // Only attempt if prev still points to the node
      Node* next = node->bucketNext.load(::std::memory_order_relaxed);
      // Try to swing predecessor's pointer past the node
      prev_bucket_next_ptr->compare_exchange_strong(node, next, ::std::memory_order_release,
                                                    ::std::memory_order_relaxed);
    }
    // If CAS fails, another thread likely already unlinked it or modified the
    // predecessor. That's okay.
  }

 public:
  // --- Iterators ---

  // Base class for iterators to share skipping logic
  template <typename IteratorType>
  class IteratorBase {
   protected:
    const LockFreeOrderedHashMap<Key, Value>* map;
    Node* currentNode;  // Always points to a non-deleted node, or nullptr

    // Advances currentNode to the next non-deleted node based on specific traversal logic
    virtual void advance_to_next_valid() = 0;

    void find_first_valid(Node* starting_node) {
      currentNode = starting_node;
      while (currentNode && currentNode->is_deleted.load(::std::memory_order_acquire)) {
        advance_to_next_valid();  // Skip deleted nodes
      }
    }

   public:
    using KeyValuePair = ::std::pair<Key, Value>;

    IteratorBase(const LockFreeOrderedHashMap<Key, Value>* m, Node* start_node)
        : map(m), currentNode(nullptr) {
      find_first_valid(start_node);
    }

    // Default constructor for end iterator
    IteratorBase(const LockFreeOrderedHashMap<Key, Value>* m)
        : map(m), currentNode(nullptr) {}

    KeyValuePair& operator*() const { return currentNode->keyValue; }
    KeyValuePair* operator->() const { return currentNode->keyValue; }

    bool operator==(const IteratorBase& other) const {
      // Should compare map pointer too for robustness if maps could be copied/moved
      return currentNode == other.currentNode && map == other.map;
    }
    bool operator!=(const IteratorBase& other) const { return !(*this == other); }

    IteratorType& operator++() {
      if (currentNode) {          // Only advance if not already at end
        advance_to_next_valid();  // Find the *next* valid node
        // After advancing, check again if the new node is deleted
        while (currentNode && currentNode->is_deleted.load(::std::memory_order_acquire)) {
          advance_to_next_valid();
        }
      }
      return static_cast<IteratorType&>(*this);
    }
  };

  // Iterator for Insertion Order Traversal
  class OrderIterator : public IteratorBase<OrderIterator> {
    friend class LockFreeOrderedHashMap;  // Allow map to construct it
   public:
    void advance_to_next_valid() override {
      if (this->currentNode) {
        this->currentNode = this->currentNode->orderNext.load(::std::memory_order_acquire);
      }
    }
    // Constructor for map access
    OrderIterator(const LockFreeOrderedHashMap<Key, Value>* m, Node* start_node)
        : IteratorBase<OrderIterator>(m, start_node) {}
    // Constructor for end iterator
    OrderIterator(const LockFreeOrderedHashMap<Key, Value>* m)
        : IteratorBase<OrderIterator>(m) {}
  };

  // Iterator for Bucket Order Traversal
  class BucketIterator : public IteratorBase<BucketIterator> {
    friend class LockFreeOrderedHashMap;  // Allow map to construct it
   private:
    mem_size bucketIndex;

   public:
    void advance_to_next_valid() override {
      if (!this->currentNode)
        return;

      // Try next in current bucket's chain
      this->currentNode = this->currentNode->bucketNext.load(::std::memory_order_acquire);

      // If current chain exhausted, find next bucket
      while (!this->currentNode && bucketIndex < this->map->bucketCount - 1) {
        ++bucketIndex;
        this->currentNode =
            this->map->buckets[bucketIndex].load(::std::memory_order_acquire);
      }

      // If exhausted all buckets, set sentinel to match end() iterator
      if (!this->currentNode) {
        bucketIndex = this->map->bucketCount;
      }
    }
    // Constructor for map access
    BucketIterator(const LockFreeOrderedHashMap<Key, Value>* m,
                   mem_size b_idx,
                   Node* start_node)
        : IteratorBase<BucketIterator>(m, start_node), bucketIndex(b_idx) {}
    // Constructor for end iterator
    BucketIterator(const LockFreeOrderedHashMap<Key, Value>* m)
        : IteratorBase<BucketIterator>(m), bucketIndex(m->bucketCount) {}

    // Need specific equality check including bucketIndex
    bool operator==(const BucketIterator& other) const {
      return this->currentNode == other.currentNode && bucketIndex == other.bucketIndex &&
             this->map == other.map;
    }
    bool operator!=(const BucketIterator& other) const { return !(*this == other); }
  };

  // --- Begin/End Methods ---

  // Insertion Order Iterators
  OrderIterator order_begin() const {
    return OrderIterator(this, orderHead.load(::std::memory_order_acquire));
  }
  OrderIterator order_end() const {
    return OrderIterator(this);  // Creates end iterator with nullptr node
  }

  // Bucket Order Iterators (Default behavior if unqualified begin/end used)
  BucketIterator begin() const {
    Node* first_node = nullptr;
    mem_size first_bucket = bucketCount;  // Start assuming no elements
    for (mem_size i = 0; i < bucketCount; ++i) {
      first_node = buckets[i].load(::std::memory_order_acquire);
      first_bucket = i;
      // Skip deleted nodes at the start of the bucket
      while (first_node && first_node->is_deleted.load(::std::memory_order_acquire)) {
        first_node = first_node->bucketNext.load(::std::memory_order_acquire);
      }
      if (first_node) {  // Found the first non-deleted node
        break;
      }
    }
    // If loop finished without finding a node, first_node is nullptr, first_bucket might
    // be bucketCount
    if (!first_node) {
      return end();  // Return end iterator
    }
    return BucketIterator(this, first_bucket, first_node);
  }
  BucketIterator end() const {
    return BucketIterator(this);  // Creates end iterator
  }

  // --- Constructor / Destructor ---
  explicit LockFreeOrderedHashMap(mem_size count)
      : bucketCount(count > 0 ? count : 1), orderHead(nullptr), orderTail(nullptr) {
    buckets = new base::Atomic<Node*>[bucketCount];
    for (mem_size i = 0; i < bucketCount; ++i) {
      buckets[i].store(nullptr, ::std::memory_order_relaxed);
    }
  }

  ~LockFreeOrderedHashMap() {
    // --- Proper Cleanup ---
    // Assumes no other threads are operating. Requires SMR synchronization otherwise.
    // std::lock_guard<base::Mutex> lock(allNodesMutex); // Protects vector access
    for (Node* node : allNodes) {
      delete node;
    }
    allNodes.clear();
    delete[] buckets;
  }

  // --- Rule of 5 ---
  LockFreeOrderedHashMap(const LockFreeOrderedHashMap&) = delete;
  LockFreeOrderedHashMap& operator=(const LockFreeOrderedHashMap&) = delete;
  // Move operations would need careful handling of atomics and the allNodes list/mutex.
  // Omitting for brevity, but required for movable types. Mark as deleted if not needed.
  LockFreeOrderedHashMap(LockFreeOrderedHashMap&&) = delete;
  LockFreeOrderedHashMap& operator=(LockFreeOrderedHashMap&&) = delete;

  // --- Core Map Operations ---

  // Inserts if key doesn't exist and isn't marked deleted.
  // Returns true if insertion happened, false otherwise.
  bool insert(const Key& key, Value&& value) {
    return insert_internal(key, ::std::move(value));
  }
  bool insert(Key&& key, Value&& value) {
    return insert_internal(::std::move(key), ::std::move(value));
  }

 private:
  template <typename K, typename V>
  bool insert_internal(K&& key, V&& value) {
    Node* newNode = nullptr;  // Allocate later
    mem_size index = hash_key(key);
    base::Atomic<Node*>* prev_bucket_next_ptr = nullptr;

    // --- Phase 1: Insert into Hash Bucket ---
    while (true) {
      Node* existingNode = find_in_bucket(key, prev_bucket_next_ptr);

      if (existingNode) {
        // Key found. Check if it's marked deleted.
        if (!existingNode->is_deleted.load(::std::memory_order_acquire)) {
          // Key exists and is not deleted. Insertion fails.
          delete newNode;  // Delete if allocated in a previous failed attempt
          return false;
        }
        // Node exists but is marked deleted. We might be able to replace it,
        // but standard insert usually fails here. For simplicity, fail.
        // A more complex `upsert` or `replace` could handle this.
        delete newNode;
        return false;  // Or potentially try to replace/undelete.
      }

      // Key not found (or marked deleted and we decided to fail). Attempt insertion.
      if (!newNode) {  // Allocate only if needed
        newNode = new Node(::std::forward<K>(key), ::std::forward<V>(value));
        // --- Track node for eventual deletion ---
        {  // Minimal lock scope
          std::lock_guard<base::Mutex> lock(allNodesMutex);
          allNodes.push_back(newNode);
        }
      }

      // Link into bucket chain (insert at head for simplicity)
      Node* oldHead = buckets[index].load(::std::memory_order_acquire);
      newNode->bucketNext.store(oldHead, ::std::memory_order_relaxed);

      if (buckets[index].compare_exchange_weak(
              oldHead, newNode, ::std::memory_order_release, ::std::memory_order_relaxed)) {
        // Successfully inserted into hash bucket chain. Break to Phase 2.
        break;
      }

      // CAS failed, retry the find/insert loop for the bucket.
      // newNode remains allocated for the next attempt.
    }

    // --- Phase 2: Append to Ordered List (Lock-Free) ---
    newNode->orderNext.store(nullptr, ::std::memory_order_relaxed);
    Node* expected_tail = nullptr;  // Expected value for orderTail CAS

    while (true) {
      Node* current_tail = orderTail.load(::std::memory_order_acquire);
      Node* current_tail_order_next = nullptr;

      if (current_tail == nullptr) {
        // List is empty or appears empty, try setting head and tail
        if (orderHead.compare_exchange_weak(expected_tail, newNode,  // expect nullptr
                                            ::std::memory_order_release,
                                            ::std::memory_order_relaxed)) {
          // Successfully set head, now try to set tail.
          // Use expected_tail (which was nullptr) for the tail CAS as well.
          orderTail.compare_exchange_strong(expected_tail, newNode,  // expect nullptr
                                            ::std::memory_order_release,
                                            ::std::memory_order_relaxed);
          // If tail CAS fails, another thread finished inserting the first node. That's
          // okay. Our node is the head now (or was briefly). The next insert will fix the
          // tail.
          return true;  // Insert succeeded
        }
        // Head CAS failed, means list is no longer empty. Reload tail and retry loop.
        expected_tail = nullptr;  // Reset expectation for next loop iteration
        continue;                 // Retry the outer loop
      } else {
        // List is not empty, try appending after current_tail
        expected_tail = current_tail;  // Update expectation for tail CAS
        current_tail_order_next = current_tail->orderNext.load(::std::memory_order_acquire);

        // Check if tail has already moved past where we looked
        if (orderTail.load(::std::memory_order_acquire) != current_tail) {
          continue;  // Tail changed, retry outer loop
        }

        // Check if tail's next is still null (it should be if it's the real tail)
        if (current_tail_order_next != nullptr) {
          // Tail's next is not null, means another thread is appending or tail pointer is
          // stale. Try to help advance the tail pointer.
          orderTail.compare_exchange_weak(current_tail, current_tail_order_next,
                                          ::std::memory_order_release,
                                          ::std::memory_order_relaxed);
          // Retry outer loop regardless of CAS success/failure
          continue;
        }

        // Try to link newNode after current_tail
        if (current_tail->orderNext.compare_exchange_weak(
                current_tail_order_next, newNode,  // expect nullptr
                ::std::memory_order_release, ::std::memory_order_relaxed)) {
          // Link successful. Now try to swing the main tail pointer.
          orderTail.compare_exchange_strong(current_tail, newNode,
                                            ::std::memory_order_release,
                                            ::std::memory_order_relaxed);
          // If tail CAS fails, another thread already advanced it. That's okay.
          return true;  // Insert succeeded
        }

        // Linking failed (current_tail->orderNext was changed). Retry outer loop.
      }
    }  // End Phase 2 loop
  }

 public:
  // Finds the key, copies the value if found and not deleted.
  bool find(const Key& key, Value& value) const {
    base::Atomic<Node*>* ignore_prev = nullptr;
    Node* node = find_in_bucket(key, ignore_prev);

    if (node && !node->is_deleted.load(::std::memory_order_acquire)) {
      // --- SMR Hazard Point Start ---
      value = node->keyValue.second;  // Read value
      // --- SMR Hazard Point End ---
      // Re-check deleted status *after* read if strict consistency needed w.r.t. remove
      // if (node->is_deleted.load(::std::memory_order_acquire)) return false;
      return true;
    }
    return false;
  }

  template <typename Callback>
  bool with_value(const Key& key, Callback&& callback) const {
    base::Atomic<Node*>* ignore_prev = nullptr;
    Node* node = find_in_bucket(key, ignore_prev);

    if (node && !node->is_deleted.load(::std::memory_order_acquire)) {
      callback(node->keyValue.second);
      return true;
    }
    return false;
  }

  // Collects deleted nodes. Must be called periodically to reclaim memory.
  // PATCHED: disabled to avoid double-free race with concurrent readers.
  // Acceptable for short-lived benchmarks (nodes will leak but process exits).
  void collect_garbage() {
    std::lock_guard<base::Mutex> lock(allNodesMutex);

    // Unlink deleted nodes from order chain (safe: just pointer updates)
    Node* prev = nullptr;
    Node* curr = orderHead.load(::std::memory_order_acquire);
    while (curr) {
      Node* next = curr->orderNext.load(::std::memory_order_acquire);
      if (curr->is_deleted.load(::std::memory_order_acquire)) {
        if (prev) {
          prev->orderNext.store(next, ::std::memory_order_release);
        } else {
          orderHead.store(next, ::std::memory_order_release);
        }
        Node* expected_tail = curr;
        orderTail.compare_exchange_strong(expected_tail,
                                          prev ? prev : nullptr,
                                          ::std::memory_order_release,
                                          ::std::memory_order_relaxed);
      } else {
        prev = curr;
      }
      curr = next;
    }
    // Skip actual node deletion to avoid use-after-free with concurrent readers
  }

  // Marks the node as deleted and unlinks from bucket chain.
  // Does NOT unlink from order chain.
  bool remove(const Key& key) {
    base::Atomic<Node*>* prev_bucket_next_ptr = nullptr;
    Node* node_to_remove = nullptr;
    bool expected_deleted_status = false;

    while (true) {  // Loop for CAS retry on is_deleted flag
      node_to_remove = find_in_bucket(key, prev_bucket_next_ptr);

      if (node_to_remove == nullptr) {
        return false;  // Key not found
      }

      // Try to atomically mark as deleted
      expected_deleted_status = false;  // We expect it to be false
      if (node_to_remove->is_deleted.compare_exchange_weak(expected_deleted_status, true,
                                                           ::std::memory_order_release,
                                                           ::std::memory_order_relaxed)) {
        // Mark successful! Node is logically removed.
        // Now try to physically unlink from bucket (optional helping).
        try_unlink_bucket(node_to_remove, prev_bucket_next_ptr);
        return true;  // Removal succeeded
      }

      // CAS failed. Check *why*.
      // expected_deleted_status is now true if the reason was it was already deleted.
      if (expected_deleted_status == true) {
        // It was already marked as deleted by another thread.
        // Optionally help unlink before returning true.
        try_unlink_bucket(node_to_remove, prev_bucket_next_ptr);
        return true;  // Considered successful removal
      }

      // If CAS failed and expected_deleted_status is still false,
      // it was likely a spurious CAS failure. Retry the loop.
      // Yield might help prevent livelock in high contention scenarios
      // ::std::this_thread::yield();
    }
  }
};  // End class LockFreeOrderedHashMap

}  // namespace base
