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
#define sleep Sleep
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

static DAP_redirect_t DAP_redirect(FILE * old, int dup2_id) {
  FILE* std_io = (FILE*)(old);
  char buf[256];
  DAP_redirect_t redr;
  int res;

  redr.fd[2] = dup(fileno(std_io));
#ifdef _WIN32
  _setmode(redr.fd[2], _O_BINARY);
#endif

  res = pipe(redr.fd);
  assert(res == 0);

  res = dup2(redr.fd[dup2_id], fileno(std_io));
  assert(res != -1);
  setvbuf(std_io, NULL, _IONBF, 0);
  return redr;
}

/*
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
*/

void DAP_send_output(const cJSON * json) {
  char* outp = cJSON_PrintUnformatted(json);
  int len_outp = strlen(outp);
  static char head_buf[42];
  pthread_mutex_lock(&MUT_O);
  sprintf(head_buf, "Content-Length: %d\r\n\r\n", len_outp);
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
  cJSON_AddItemReferenceToObject(obj, "command", cJSON_GetObjectItem(req, "command"));
  cJSON_AddItemReferenceToObject(obj, "request_seq", cJSON_GetObjectItem(req, "seq"));
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
  if (strcmp(cmd, "next") == 0) {
    assert(0);  /* TODO: IMPLEMENT */
  }
  if (strcmp(cmd, "stepIn") == 0) {
    assert(0);  /* TODO: IMPLEMENT */
  }
  if (strcmp(cmd, "stepOut") == 0) {
    assert(0);  /* TODO: IMPLEMENT */
  }
  if (strcmp(cmd, "continue") == 0) {
    assert(0);  /* TODO: IMPLEMENT */
  }
  if (strcmp(cmd, "evaluate") == 0) {
    assert(0);  /* TODO: IMPLEMENT */
  }
  if (strcmp(cmd, "variables") == 0) {
    assert(0);  /* TODO: IMPLEMENT */
  }
  if (strcmp(cmd, "scopes") == 0) {
    assert(0);  /* TODO: IMPLEMENT */
  }
  if (strcmp(cmd, "stackTrace") == 0) {
    assert(0);  /* TODO: IMPLEMENT */
  }
  if (strcmp(cmd, "threads") == 0) {
    assert(0);  /* TODO: IMPLEMENT */
  }
  if (strcmp(cmd, "pause") == 0) {
    assert(0);  /* TODO: IMPLEMENT */
  }
  if (strcmp(cmd, "setBreakpoints") == 0) {
    assert(0);  /* TODO: IMPLEMENT */
  }
  if (strcmp(cmd, "source") == 0) {
    assert(0);  /* TODO: IMPLEMENT */
  }
  if (strcmp(cmd, "initialize") == 0) {
    return DAP_respond_dispose(req, 1, cJSON_CreateObject())
        || DAP_send_output_dispose(DAP_create_event("initialized", NULL));
  }
  if (strcmp(cmd, "launch") == 0) {
    return DAP_respond_dispose(req, 1, cJSON_CreateObject());
  }
  if (strcmp(cmd, "attach") == 0) {
    return DAP_respond_dispose(req, 1, cJSON_CreateObject());
  }
  if (strcmp(cmd, "disconnect") == 0) {
    close_std_libs();
    DAP_respond_dispose(req, 1, cJSON_CreateObject());
    return 2;
  }
  return -2;
}
#undef END_RESP

static void * DAP_handle_stdin(void * arg) {
  static char head_buf[42];
  while (1) {
    int hp = 0;
    while (hp < 16) {
      if (read(redir[0].fd[2], head_buf + hp, 16 - hp) == 0)
        return NULL;
    }
    head_buf[16] = '\0';
    assert(strcmp(head_buf, "Content-Length: ") == 0);
    for (int p = 0; p < 39; p++)
    {
      read(redir[0].fd[2], head_buf + p, 1);
      if (head_buf[p] == '\n')
      {
        head_buf[p + 1] = '\0';
        break;
      }
    }
    int size_body;
    sscanf(head_buf, "%d", &size_body);
    do {
      read(redir[0].fd[2], head_buf, 1);
    } while (head_buf[0] != '\n');
    char* body = malloc(size_body + 1);
    assert(body);
    read(redir[0].fd[2], body, size_body);
    body[size_body] = '\0';
    if (DAP_handle_request(cJSON_Parse(body)) == 2)
    {
      free(body);
      break;
    }
    free(body);
  }
  return NULL;
}

static void * DAP_handle_stdout(void * arg) {
  static char buffer[4097];
  int bufread = 8;
  while (1) {
    int nc = read(redir[1].fd[0], buffer, bufread);
    if (nc > 0) {
      buffer[nc] = '\0';
      cJSON * body = cJSON_CreateObject();
      cJSON_AddItemToObject(body, "category", cJSON_CreateString("stdout"));
      cJSON_AddItemToObject(body, "output", cJSON_CreateString(buffer));
      DAP_send_output_dispose(DAP_create_event("output", body));
    }
    if (nc == bufread)
    {
      if (bufread < 4096) bufread *= 2;
    }
    else
      bufread = 8;
  }
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
  redir[0] = DAP_redirect(stdin, 0);
  redir[1] = DAP_redirect(stdout, 1);
  freopen("error.log", "a", stderr);
  pthread_create(threads + 0, NULL, DAP_handle_stdin, NULL);
  pthread_create(threads + 1, NULL, DAP_handle_stdout, NULL);
  /* pthread_create(threads + 2, NULL, DAP_handle_stderr, NULL);
  pthread_join(threads[2], NULL); */
  sleep(1000);
  write(fileno(stdout), "write\n", 6);
  fputs("fputs\n", stdout);
  fprintf(stdout, "fprintf");
  // write(redir[1].fd[1], "2222222222\n", redir[1].fd[1]);
  pthread_join(threads[0], NULL);
  sleep(1000);
  pthread_cancel(threads[1]);
  DAP_send_output_dispose(DAP_create_event("terminated", NULL));
  DAP_send_output_dispose(DAP_create_event("exited", cJSON_CreateRaw("{\"exitCode\": 0}")));
  return 0;
}
#endif
