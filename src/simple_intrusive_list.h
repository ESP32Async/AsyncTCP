// Simple intrusive list class

template<typename T> class simple_intrusive_list {
  static_assert(std::is_same<decltype(std::declval<T>().next), T *>::value, "Template type must have public 'T* next' member");

private:
  T *_head;
  T **_tail;

public:
  // Static utility methods
  static size_t list_size(T *chain) {
    size_t count = 0;
    for (auto c = chain; c != nullptr; c = c->next) {
      ++count;
    }
    return count;
  }

  static void delete_list(T *chain) {
    while (chain) {
      auto t = chain;
      chain = chain->next;
      delete t;
    }
  }

public:
  // Object methods

  simple_intrusive_list() : _head(nullptr), _tail(&_head) {}
  ~simple_intrusive_list() {
    clear();
  }

  // Noncopyable, nonmovable
  simple_intrusive_list(const simple_intrusive_list<T> &) = delete;
  simple_intrusive_list(simple_intrusive_list<T> &&) = delete;
  simple_intrusive_list<T> &operator=(const simple_intrusive_list<T> &) = delete;
  simple_intrusive_list<T> &operator=(simple_intrusive_list<T> &&) = delete;

  void push_back(T *obj) {
    if (obj) {
      *_tail = obj;
      _tail = &obj->next;
    }
  }

  void push_front(T *obj) {
    if (obj) {
      if (_head == nullptr) {
        _tail = &obj->next;
      }
      obj->next = _head;
      _head = obj;
    }
  }

  T *pop_front() {
    auto rv = _head;
    if (_head) {
      if (_tail == &_head->next) {
        _tail = &_head;
      }
      _head = _head->next;
    }
    return rv;
  }

  void clear() {
    // Assumes all elements were allocated with "new"
    delete_list(_head);
    _head = nullptr;
    _tail = &_head;
  }

  size_t size() const {
    return list_size(_head);
  }

  T *remove_if(const std::function<bool(T &)> &condition) {
    T *removed = nullptr;
    auto **current_ptr = &_head;
    while (*current_ptr != nullptr) {
      auto *current = *current_ptr;
      if (condition(*current)) {
        *current_ptr = current->next;
        if (current->next == nullptr) {
          _tail = current_ptr;
        }
        current->next = removed;
        removed = current;
        // do not advance current_ptr
      } else {
        // advance current_ptr
        current_ptr = &(*current_ptr)->next;
      }
    }

    return removed;
  }

  T *begin() const {
    return _head;
  }
};  // class simple_intrusive_list
