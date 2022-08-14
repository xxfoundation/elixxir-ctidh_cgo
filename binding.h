#ifndef _BINDING_H
#define _BINDING_H

#define NAMESPACEBITS(x) highctidh_512_##x

#include <csidh.h>

private_key load_private_key(char* raw_key);
public_key load_public_key(char* raw_key);

#endif
