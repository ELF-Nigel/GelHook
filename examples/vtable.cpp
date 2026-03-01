#include <iostream>

#define GELHOOK_IMPLEMENTATION
#include "../gelhook.h"


struct Base {
  virtual ~Base() = default;
  virtual int add(int x) { return x + 1; }
};

static int hooked_add(Base *self, int x) {
  (void)self;
  return x + 100;
}

int main() {
  gh_set_log_level(GH_LOG_DEBUG);
  Base b;
  void **vtable = *reinterpret_cast<void ***>(&b);
  void *orig = nullptr;

  if (gh_vtable_hook(vtable, 1, (void *)hooked_add, &orig) != GH_OK) {
    std::cout << "vtable hook failed: " << gh_last_error() << "\n";
    return 1;
  }

  std::cout << "add(5) => " << b.add(5) << "\n";
  return 0;
}
