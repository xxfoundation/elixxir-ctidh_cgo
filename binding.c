
#include "binding.h"
#include <csidh.h>

private_key load_private_key(char* raw_key) {
  private_key priv_key;
  for (int8_t i = 0;i < primes_num;++i) {
    priv_key.e[i] = raw_key[i];
  }
  return priv_key;
}


public_key load_public_key(char* raw_key) {
  public_key pub_key;
  for (int64_t i = 0;i < primes_num;++i) {

  }
  return pub_key;
}
