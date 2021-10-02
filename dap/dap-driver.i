#if MIR_DAP
#undef strings
#include "cJSON.h"
#include <stdio.h>
#include <assert.h>

#if defined(__unix__) || defined(__unix) || \
    (defined(__APPLE__) && defined(__MACH__))
#include <fcntl.h>
#include <unistd.h>
#include <pthread.h>
#endif

#ifdef _WIN32
#include <io.h>
/* On windows MinGW/CYGwin should be used */
#define _O_BINARY 0x8000
#define pipe(X) _pipe(X, 4096, _O_BINARY)
#define fileno _fileno
#define dup _dup
#define dup2 _dup2
#define read _read
#define write _write
#endif

typedef struct {
  int fd[3];
} DAP_redirect_t;

static DAP_redirect_t DAP_redirect(FILE * old) {
  FILE* std_io = (FILE*)(old);
  char buf[256];
  DAP_redirect_t redr;
  int res;

  redr.fd[2] = dup(fileno(std_io));

  res = pipe(redr.fd);
  assert(res == 0);

  res = dup2(redr.fd[1], fileno(std_io));
  assert(res != -1);
  return redr;
}

static cJSON * DAP_next_message() {
  static char content[255];
  if (!gets(content))
    exit(0);
  int clen;
  sscanf(content, "Content-Length: %d", &clen);
  gets(content);
  char* command = malloc(clen + 1);
  assert(clen == fread(command, 1, clen, stdin));
  command[clen] = '\0';
  cJSON * jo = cJSON_Parse(command);
  free(command);
  return jo;
}

void start_insn_trace (MIR_context_t ctx, const char *name, func_desc_t func_desc, code_t pc, size_t nops)
{
  
}

#define END_RESP cJSON_Delete(req); return
static void DAP_handle_request(cJSON * req) {
  const char* cmd = cJSON_GetStringValue(cJSON_GetObjectItem(req, "command"));
  if (strcmp(cmd, "initialize")) {

  }
}
#undef END_RESP

static void * DAP_handle_stdin(void * arg) {
  DAP_redirect(stdin);
}

static void * DAP_handle_stdout(void * arg) {
  write(DAP_redirect(stdout).fd[2], "Test 1", 6);
}

static void * DAP_handle_stderr(void * arg) {
  DAP_redirect(stderr);
}

int main(int argc, const char ** argv) {
  pthread_t threads[3];
  pthread_create(threads + 0, NULL, DAP_handle_stdin, NULL);
  pthread_create(threads + 1, NULL, DAP_handle_stdout, NULL);
  pthread_create(threads + 2, NULL, DAP_handle_stderr, NULL);
  pthread_join(threads[0], NULL);
  pthread_join(threads[1], NULL);
  pthread_join(threads[2], NULL);
  return 0;
}
#endif
