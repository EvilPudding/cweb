#include "cemplate.h"

#include <assert.h>
#include <dlfcn.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

typedef struct
{
	char *name;
	int(*generator)(FILE*, void*);
	void *lib;
} Cemplate;

static int cemplate_is_older(Cemplate *this, const char *p2)
{
	if(this->generator == NULL) return 1;
	char p1[1000];
	sprintf(p1, "templates/%s.so", this->name);

	struct stat file_stat1; struct stat file_stat2;
	int err1 = stat(p1, &file_stat1);
	int err2 = stat(p2, &file_stat2);
	if(err1 && err2) return -1;
	if(err1) return 1;
	if(err2) return 0;
	return file_stat1.st_mtime < file_stat2.st_mtime;
}

static int cemplate_parse(const char *in)
{
	char out[1000];
	char out_name[128];
	strcpy(out_name, in);
	for(char *iter = out_name; *iter; iter++) if(*iter == '/') *iter = '_';
	sprintf(out, "templates/tmp/%s", out_name);
	const char start[] = "/*%";
	const char end[] = "%*/";

	FILE *fin = fopen(in, "r");
	if(!fin)
	{
		/* printf("File '%s' does not exist.\n", in); */
		return 0;
	}
	FILE *fout = fopen(out, "w");
	if(!fout) return 0;
	fprintf(fout, "#ifndef CEMPLATE_GEN\n#define CEMPLATE_GEN\n#endif\n");

	char *line = NULL;
	size_t len = 0;
	ssize_t read;

	int normal_line = 0;

	int block = 'N';
	while ((read = getline(&line, &len, fin)) != -1)
	{
		normal_line++;
		char *iter;
		int escaped = 0;
		for(iter = line;*iter!='\n' && *iter!='\r' && *iter!='\0'; iter++)
		{
			if(block == 'N')
			{
				if(!strncmp(iter, start, sizeof(start) - 1))
				{
					block = 'T';
					iter += sizeof(start) - 2;
					fputs("fprintf(fp, \"", fout);
					continue;
				}
				fputc(*iter, fout);
			}
			else if(block == 'T')
			{
				if(!strncmp(iter, end, sizeof(end) - 1))
				{
					block = 'N';
					iter += sizeof(end) - 2;
					fprintf(fout, "\\n\");\n#line %d \"%s\"", normal_line, in);
					continue;
				}
				if(*iter == '"' || *iter == '%') fputc('\\', fout);
				fputc(*iter, fout);
			}
		}
		if(*iter != '\0')
		{
			if(block == 'N')
			{
				fputc(*iter, fout);
			}
			else
			{
				fputc('\\', fout); fputc('n', fout);
			}
		}
	}

	if(line) free(line);
	fclose(fin);
	fclose(fout);
	return 1;
}

static inline int cemplate_create_dirs()
{
	return !system("mkdir -p templates/tmp");
}

static int cemplate_compile_aux(const char *file)
{
	char out_name[128];
	strcpy(out_name, file);
	for(char *iter = out_name; *iter; iter++) if(*iter == '/') *iter = '_';

	char command[1000];
	char format[] = "gcc -I. -O3 -shared -o templates/%s.so -fPIC templates/tmp/%s.c";
	sprintf(command, format, out_name, out_name);
	return !system(command);
}

static int cemplate_update_lib(Cemplate *this)
{
	char tmp[1000];
	sprintf(tmp, "templates/%s.so", this->name);

	if(this->lib) dlclose(this->lib);
	this->lib = dlopen(tmp, RTLD_LAZY);
	if(this->lib)
	{
		this->generator = dlsym(this->lib, "main");
		return 1;
	}
	return 0;
}

static Cemplate *get_template(const char *file)
{
	static Cemplate **templates = NULL;
	static size_t templates_num = 0;

	char *name = strdup(file);
	char *dot_index = rindex(name, '.');
	if(!dot_index)
	{
		free(name);
		return NULL;
	}
	*dot_index = '\0';
	for(char *iter = name; *iter; iter++) if(*iter == '/') *iter = '_';

	int i;
	for(i = 0; i < templates_num; i++)
	{
		if(!strcmp(name, templates[i]->name))
		{
			free(name);
			return templates[i];
		}
	}

	templates_num++;
	templates = realloc(templates, templates_num * sizeof(Cemplate*));
	Cemplate *temp = templates[templates_num - 1] = calloc(1, sizeof(Cemplate));

	temp->name = name;
	cemplate_update_lib(temp);
	return temp;
}

int cemplate_generate_to_stream(const char *in, FILE *stream, void *data)
{
	Cemplate *temp = get_template(in);
	if(!temp)
	{
		return 0;
	}
	if(cemplate_is_older(temp, in))
	{
		/* printf("Template not up to date, recompiling.\n"); */
		if(!cemplate_create_dirs())
		{
			perror("Failed to create template directories.\n"); return 0;
		}
		if(!cemplate_parse(in))
		{
			perror("Failed to parse template.\n"); return 0;
		}
		if(!cemplate_compile_aux(temp->name))
		{
			perror("Failed to compile template.\n"); return 0;
		}
		if(!cemplate_update_lib(temp))
		{
			perror("Failed to open template.\n"); return 0;
		}
	}

	return temp->generator(stream, data);
}

int cemplate_generate_to_string(const char *in, char **string, void *data)
{
	size_t size = 0;
	FILE *stream = open_memstream(string, &size);
	int result = cemplate_generate_to_stream(in, stream, data);
	fclose(stream);

	if(result == -1)
	{
		free(*string);
		*string = NULL;
		return -1;
	}
	return (int)size;
}

int cemplate_generate_to_file(const char *in, const char *file_out, void *data)
{
	FILE *fd = file_out ? fopen(file_out, "w") : stdout;
	int result = cemplate_generate_to_stream(in, fd, data);
	fclose(fd);
	return result;
}

#ifdef UNIT_TEST
int main(int argc, char **argv)
{
	char *out;
	if(argc < 2)
	{
		printf("Usage: %s [in] [out=stdin] \n", argv[0]);
		return 1;
	}
	out = argc == 3 ? argv[2] : NULL;

	return cemplate_generate_to_file(argv[1], out, NULL);
}
#endif
