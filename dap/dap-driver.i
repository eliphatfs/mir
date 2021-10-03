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
  int fd[3];  /* Read-end, Write-end, Original-fd */
} DAP_redirect_t;
#define MUT_BOUND 10
static pthread_mutex_t mutex[MUT_BOUND];
static pthread_cond_t cond[MUT_BOUND];
static DAP_redirect_t redir[3];  /* STDIN, STDOUT, STDERR (STDERR not redirected now) */
#define MUT_I mutex[0]
#define MUT_O mutex[1]
#define MUT_CA_TRACE mutex[2]
#define COND_CA cond[0]

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

void DAP_send_output(const cJSON * json) {
  char* outp = cJSON_PrintUnformatted(json);
  int len_outp = strlen(outp);
  static char head_buf[42];
  sprintf(head_buf, "Content-Length: %d\r\n\r\n", len_outp);
  pthread_mutex_lock(&MUT_O);
  write(redir[1].fd[2], head_buf, strlen(head_buf));
  write(redir[1].fd[2], outp, len_outp);
  pthread_mutex_unlock(&MUT_O);
  cJSON_free(outp);
}

int DAP_send_output_dispose(cJSON * json) {
  DAP_send_output(json);
  cJSON_Delete(json);
  return 0;
}

void start_insn_trace (MIR_context_t ctx, const char *name, func_desc_t func_desc, code_t pc, size_t nops)
{
  
}

static cJSON * DAP_create_message(const char* msg_kind) {
  static unsigned long seq = 4;
  cJSON * obj = cJSON_CreateObject();
  cJSON_AddItemToObject(obj, "type", cJSON_CreateString(msg_kind));
  cJSON_AddItemToObject(obj, "seq", cJSON_CreateNumber(seq += 4));
  return obj;
}

static cJSON * DAP_create_event(const char* event_kind, cJSON * body) {
  cJSON * obj = DAP_create_message("event");
  cJSON_AddItemToObject(obj, "event", cJSON_CreateString(event_kind));
  if (body)
    cJSON_AddItemToObject(obj, "body", body);
  return obj;
}

static cJSON * DAP_create_response(cJSON * req, int success, cJSON * body_or_error) {
  cJSON * obj = DAP_create_message("response");
  cJSON_AddItemToObject(obj, "success", cJSON_CreateBool(success));
  cJSON_AddItemToObject(obj, "command", cJSON_GetObjectItem(req, "command"));
  cJSON_AddItemToObject(obj, "request_seq", cJSON_GetObjectItem(req, "seq"));
  if (body_or_error)
  {
    if (success)
      cJSON_AddItemToObject(obj, "body", body_or_error);
    else
      cJSON_AddItemToObject(obj, "message", body_or_error);
  }
  return obj;
}

static int DAP_respond_dispose(cJSON * req, int success, cJSON * body_or_error)
{
  DAP_send_output_dispose(DAP_create_response(req, success, body_or_error));
  cJSON_Delete(req);
  return 0;
}

static int DAP_handle_request(cJSON * req) {
  const char* cmd = cJSON_GetStringValue(cJSON_GetObjectItem(req, "command"));
  if (strcmp(cmd, "initialize")) {
    return DAP_respond_dispose(req, 1, cJSON_CreateObject())
         | DAP_send_output_dispose(DAP_create_event("initialized", NULL));
  }
}
#undef END_RESP

static void * DAP_handle_stdin(void * arg) {
}

static void * DAP_handle_stdout(void * arg) {
}

/*
static void * DAP_handle_stderr(void * arg) {
  DAP_redirect(stderr);
}
*/

int main(int argc, const char ** argv) {
  pthread_t threads[2];
  for (int i = 0; i < MUT_BOUND; i++)
  {
    pthread_mutex_init(mutex + i, NULL);
    pthread_cond_init(cond + i, NULL);
  }
  redir[0] = DAP_redirect(stdin);
  redir[1] = DAP_redirect(stdout);
  pthread_create(threads + 0, NULL, DAP_handle_stdin, NULL);
  pthread_create(threads + 1, NULL, DAP_handle_stdout, NULL);
  /* pthread_create(threads + 2, NULL, DAP_handle_stderr, NULL);
  pthread_join(threads[0], NULL);
  pthread_join(threads[1], NULL);
  pthread_join(threads[2], NULL); */
  return 0;
}
#endif
