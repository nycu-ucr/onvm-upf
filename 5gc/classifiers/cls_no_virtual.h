#pragma once
#include <type_traits>
#define CLS_ENSURE_NO_VIRTUAL(T) \
  static_assert(!std::is_polymorphic<T>::value, #T " must be non-polymorphic (no virtual)")
