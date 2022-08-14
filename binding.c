
#include "binding.h"
#include <csidh.h>

private_key load_private_key(char* raw_key) {
  return *((private_key *)raw_key);
}

public_key load_public_key(char *raw_key) {
  return *((public_key *)raw_key);
}
