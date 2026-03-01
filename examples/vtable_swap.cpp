#include <iostream>

#define GELHOOK_IMPLEMENTATION
#include "../gelhook.h"

struct Base {
  virtual ~Base() = default;
  virtual int add(int x) { return x + 1; }
  virtual int mul(int x) { return x * 2; }
};

static int hooked_add(Base *self, int x) {
  (void)self;
  return x + 1000;
}

int main() {
  Base b;
  void *orig = nullptr;
  void **new_table = nullptr;

  if (gh_vtable_swap(&b, 2, 0, (void *)hooked_add, &orig, &new_table) != GH_OK) {
    std::cout << "vtable swap failed: " << gh_last_error() << "\n";
    return 1;
  }

  std::cout << "add(5) => " << b.add(5) << "\n";
  std::cout << "mul(5) => " << b.mul(5) << "\n";
  return 0;
}
