#ifndef CEMPLATE_H
#define CEMPLATE_H

#ifdef CEMPLATE_GEN
#include <stdio.h>
#endif

int cemplate_generate(const char *in, const char *out, void *data);

#endif /* !CEMPLATE_H */
