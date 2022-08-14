
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
  for (long i = 0; i < primes_num; ++i) {
      pub_key.A.x.c[i] = (uint64_t)raw_key[i*8];
  }
  return pub_key;
}
