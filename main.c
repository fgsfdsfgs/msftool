#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <dirent.h>
#include <unistd.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#ifdef _WIN32
# define UMKDIR(x, y) mkdir(x)
#else
# define UMKDIR(x, y) mkdir(x, y)
#endif

#define MSF_MAGIC "\x00\x00\x03\xE7\x00\x00\x00\x02"
#define MSF_MAX_NAMELEN 255 // limited by the length field being 1 byte

/* all the 32-bit fields are big endian */

struct msf_entry {
  uint32_t ofs;
  uint32_t len;
  uint8_t namelen;
  char name[MSF_MAX_NAMELEN + 1];
};

struct msf_header {
  uint8_t magic[8]; // MSF_MAGIC
  uint32_t num_files;
};

static inline uint8_t read8(FILE *f) {
  uint8_t v;
  fread(&v, sizeof(v), 1, f);
  return v;
}

static inline uint32_t read32be(FILE *f) {
  uint32_t v;
  fread(&v, sizeof(v), 1, f);
  return __builtin_bswap32(v);
}

static inline uint8_t write8(FILE *f, uint8_t v) {
  fwrite(&v, sizeof(v), 1, f);
}

static inline void write32be(FILE *f, uint32_t v) {
  v = __builtin_bswap32(v);
  fwrite(&v, sizeof(v), 1, f);
}

static int mkpath(const char *path, const int mode) {
  int ret = -1;
  char tmp[strlen(path) + 1];
  memcpy(tmp, path, sizeof(tmp) - 1);
  tmp[sizeof(tmp) - 1] = 0;

  for (char *p = tmp; *p; ++p) {
    if (*p == '/' || *p == '\\') {
      // dir separator found, terminate string temporarily and call mkdir
      const char orig = *p;
      *p = 0;
      if (UMKDIR(tmp, mode) >= 0)
        ret = 0;
      *p = orig;
    }
  }

  return ret;
}

static int msf_unpack(FILE *f, const char *dir) {
  uint8_t *buf = NULL;
  uint32_t buflen = 0;
  FILE *fout = NULL;
  int ret = -1;
  char path[MSF_MAX_NAMELEN * 2 + 1];
  struct msf_header msf;
  struct msf_entry *ent = NULL;
  memset(&msf, 0, sizeof(msf));

  fread(msf.magic, sizeof(msf.magic), 1, f);
  if (memcmp(msf.magic, MSF_MAGIC, sizeof(msf.magic)) != 0) {
    fprintf(stderr, "error: invalid MSF magic\n");
    goto _end;
  }

  msf.num_files = read32be(f);

  ent = calloc(msf.num_files, sizeof(struct msf_entry));
  if (!ent) {
    fprintf(stderr, "error: out of memory allocating msf table\n");
    goto _end;
  }

  // read all file headers first to reduce seeking
  for (uint32_t i = 0; i < msf.num_files; ++i) {
    ent[i].ofs = read32be(f);
    ent[i].len = read32be(f);
    ent[i].namelen = read8(f);
    if (ent[i].namelen > MSF_MAX_NAMELEN) {
      fprintf(stderr, "warning: entry %u has name longer than %u (%u)\n", i, MSF_MAX_NAMELEN, ent[i].namelen);
      ent[i].namelen = MSF_MAX_NAMELEN;
    }
    fread(ent[i].name, ent[i].namelen, 1, f);
  }

  printf("unpacking %u files:\n", msf.num_files);

  for (uint32_t i = 0; i < msf.num_files; ++i) {
    printf("... %s\n", ent[i].name);

    // ensure copy buffer is large enough
    if (ent[i].len > buflen) {
      // add 1mb of overhead to not alloc as often
      buflen = ent[i].len + 1024 * 1024;
      buf = realloc(buf, buflen);
      if (!buf) {
        fprintf(stderr, "error: out of memory allocating %u bytes\n", buflen);
        goto _end;
      }
    }

    snprintf(path, sizeof(path), "%s/%s", dir, ent[i].name);

    // make file path
    mkpath(path, 0755);

    // read file contents
    fseek(f, ent[i].ofs, SEEK_SET);
    fread(buf, ent[i].len, 1, f);

    // write them back
    fout = fopen(path, "wb");
    if (!fout) {
      fprintf(stderr, "error: could not open `%s` for writing\n", path);
      goto _end;
    }
    fwrite(buf, ent[i].len, 1, fout);
    fclose(fout);
  }

  // success
  ret = 0;

_end:
  free(ent);
  free(buf);
  return ret;
}

static uint32_t msf_walk(const char *dirpath, uint32_t baselen, struct msf_entry **ent, uint32_t *datastart, uint32_t fcount) {
  char path[MSF_MAX_NAMELEN * 2 + 1];
  struct stat stbuf;
  struct dirent *dent = NULL;

  DIR *dir = opendir(dirpath);
  if (!dir) {
    fprintf(stderr, "error: could not open directory `%s`\n", dirpath);
    return 0;
  }

  while ((dent = readdir(dir)) != NULL) {
    // skip `.`, `..` and hidden files
    if (dent->d_name[0] == '.') continue;

    // get size and type
    snprintf(path, sizeof(path), "%s/%s", dirpath, dent->d_name);
    if (stat(path, &stbuf) < 0) {
      fprintf(stderr, "error: couldn't stat `%s`\n", path);
      return 0;
    }

    // if directory, recurse; if file, expand table
    if (S_ISDIR(stbuf.st_mode)) {
      fcount = msf_walk(path, baselen, ent, datastart, fcount);
    } else if (S_ISREG(stbuf.st_mode)) {
      const uint32_t i = fcount++;
      *ent = realloc(*ent, fcount * sizeof(struct msf_entry));
      if (!*ent) {
        fprintf(stderr, "error: out of memory allocating msf file table\n");
        return 0;
      }

      (*ent)[i].ofs = 0;
      (*ent)[i].len = stbuf.st_size;
      (*ent)[i].namelen = strlen(path) - baselen;
      memcpy((*ent)[i].name, path + baselen, (*ent)[i].namelen);
      (*ent)[i].name[(*ent)[i].namelen] = 0;
      *datastart += sizeof(uint32_t) * 2 + 1 + (*ent)[i].namelen;
    }
  }

  closedir(dir);

  return fcount;
}

static int msf_pack(FILE *f, const char *dirpath) {
  uint8_t *buf = NULL;
  uint32_t buflen = 0;
  FILE *fin = NULL;
  int ret = -1;
  uint32_t datastart = sizeof(struct msf_header);
  uint32_t curofs = 0;
  char path[MSF_MAX_NAMELEN * 2 + 1];
  struct msf_header msf = { MSF_MAGIC, 0 };
  struct msf_entry *ent = NULL;

  printf("scanning directory `%s`:\n", dirpath);

  // recursively walk target directory
  msf.num_files = msf_walk(dirpath, strlen(dirpath) + 1, &ent, &datastart, 0);
  if (msf.num_files == 0) goto _end;

  printf("\nwriting msf:\n");

  // write header
  fwrite(msf.magic, sizeof(msf.magic), 1, f);
  write32be(f, msf.num_files);

  // write file table
  curofs = datastart;
  for (uint32_t i = 0; i < msf.num_files; ++i) {
    ent[i].ofs = curofs;
    write32be(f, ent[i].ofs);
    write32be(f, ent[i].len);
    write8(f, ent[i].namelen);
    fwrite(ent[i].name, ent[i].namelen, 1, f);
    curofs += ent[i].len;
  }

  // data starts where all the header bullshit ends
  assert(datastart == ftell(f));

  // write files
  for (uint32_t i = 0; i < msf.num_files; ++i) {
    printf("... %s\n", ent[i].name);

    // ensure copy buffer is large enough
    if (ent[i].len > buflen) {
      // add 1mb of overhead to not alloc as often
      buflen = ent[i].len + 1024 * 1024;
      buf = realloc(buf, buflen);
      if (!buf) {
        fprintf(stderr, "error: out of memory allocating %u bytes\n", buflen);
        goto _end;
      }
    }

    // read input file
    snprintf(path, sizeof(path), "%s/%s", dirpath, ent[i].name);
    fin = fopen(path, "rb");
    if (!fin) {
      fprintf(stderr, "error: could not read `%s`\n", path);
      goto _end;
    }
    fread(buf, ent[i].len, 1, fin);
    fclose(fin);

    // write it back
    fwrite(buf, ent[i].len, 1, f);
  }

_end:
  free(ent);
  free(buf);
  return ret;
}

static void usage(void) {
  printf("usage: msftool pack|unpack <msf> <path>\n");
}

int main(int argc, char **argv) {
  if (argc < 4) {
    usage();
    return -1;
  }

  const int do_pack = !strcmp(argv[1], "pack");
  const char *msf_path = argv[2];
  const char *dir = argv[3];

  FILE *msf_file = fopen(msf_path, do_pack ? "wb" : "rb");
  if (!msf_file) {
    fprintf(stderr, "error: could not open `%s`\n", msf_path);
    return -1;
  }

  int ret;
  if (do_pack)
    ret = msf_pack(msf_file, dir);
  else
    ret = msf_unpack(msf_file, dir);

  fclose(msf_file);

  return ret;
}
