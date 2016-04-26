#ifndef CEMPLATE_H
#define CEMPLATE_H

#include <stdio.h>

int cemplate_generate_to_file(const char *in, const char *out, void *data);

int cemplate_generate_to_stream(const char *in, FILE *stream, void *data);

int cemplate_generate_to_string(const char *in, char **string, void *data);

#endif /* !CEMPLATE_H */
