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
#define MUT_LAUNCH mutex[3]
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
  char* outp = cJSON_Print(json);
  int len_outp = strlen(outp);
  static char head_buf[42];
  pthread_mutex_lock(&MUT_O);
  sprintf(head_buf, "Content-Length: %d\r\n\r\n", len_outp);
  write(redir[1].fd[2], head_buf, strlen(head_buf));
  write(redir[1].fd[2], outp, len_outp);
  pthread_mutex_unlock(&MUT_O);
  fprintf(stderr, "< %s\n", outp);
  fflush(stderr);
  cJSON_free(outp);
}

int DAP_send_output_dispose(cJSON * json) {
  DAP_send_output(json);
  cJSON_Delete(json);
  return 0;
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

static void DAP_output_event(const char* cat, const char * msg)
{
  cJSON * body = cJSON_CreateObject();
  cJSON_AddItemToObject(body, "category", cJSON_CreateString(cat));
  cJSON_AddItemToObject(body, "output", cJSON_CreateString(msg));
  DAP_send_output_dispose(DAP_create_event("output", body));
}

volatile char dap_wait_on_next_insn_p = 1;
volatile int wait_line = 1;
char const* dap_wait_reason = "entry";
char const* wait_filename = "";
char const* wait_filepath = "";
void start_insn_trace (MIR_context_t ctx, const char *name, func_desc_t func_desc, code_t pc, size_t nops)
{
  if (dap_wait_on_next_insn_p)
  {
    dap_wait_on_next_insn_p = 0;
    wait_line = ((MIR_insn_t)pc[1].a)->src_lno;
    /* printf("%s\n", name); */
    cJSON * body = cJSON_CreateObject();
    cJSON_AddStringToObject(body, "reason", dap_wait_reason);
    cJSON_AddNumberToObject(body, "threadId", 0);
    DAP_send_output_dispose(DAP_create_event("stopped", body));
    pthread_mutex_lock(&MUT_CA_TRACE);
    pthread_cond_wait(&COND_CA, &MUT_CA_TRACE);
    pthread_mutex_unlock(&MUT_CA_TRACE);
  }
}

static int DAP_handle_request(cJSON * req) {
  const char* cmd = cJSON_GetStringValue(cJSON_GetObjectItem(req, "command"));
  char * ret = cJSON_Print(req);
  fprintf(stderr, "> %s\n", ret);
  fflush(stderr);
  cJSON_free(ret);
  if (strcmp(cmd, "next") == 0) {
    assert(0);  /* TODO: IMPLEMENT */
  }
  if (strcmp(cmd, "stepIn") == 0) {
    pthread_cond_broadcast(&COND_CA);
    dap_wait_reason = "step";
    dap_wait_on_next_insn_p |= 1;
    return DAP_respond_dispose(req, 1, cJSON_CreateObject());
  }
  if (strcmp(cmd, "stepOut") == 0) {
    assert(0);  /* TODO: IMPLEMENT */
  }
  if (strcmp(cmd, "continue") == 0) {
    pthread_cond_broadcast(&COND_CA);
    return DAP_respond_dispose(req, 1, cJSON_CreateObject());
  }
  if (strcmp(cmd, "evaluate") == 0) {
    assert(0);  /* TODO: IMPLEMENT */
  }
  if (strcmp(cmd, "variables") == 0) {
    assert(0);  /* TODO: IMPLEMENT */
  }
  if (strcmp(cmd, "scopes") == 0) {
    cJSON * body = cJSON_CreateObject();
    cJSON * scopes = cJSON_AddArrayToObject(body, "scopes");
    /* TODO: IMPLEMENT */
    return DAP_respond_dispose(req, 1, body);
  }
  if (strcmp(cmd, "stackTrace") == 0) {
    cJSON * body = cJSON_CreateObject();
    cJSON * stackFrames = cJSON_AddArrayToObject(body, "stackFrames");
    cJSON_AddNumberToObject(body, "totalFrames", 1);
    cJSON * frame = cJSON_CreateObject();
    cJSON_AddItemToArray(stackFrames, frame);
    cJSON_AddNumberToObject(frame, "line", wait_line);
    cJSON_AddNumberToObject(frame, "column", 0);
    cJSON_AddNumberToObject(frame, "id", 1000);
    cJSON_AddStringToObject(frame, "name", "<top>");
    cJSON * src = cJSON_AddObjectToObject(frame, "source");
    cJSON_AddStringToObject(src, "name", wait_filename);
    cJSON_AddStringToObject(src, "path", wait_filepath);
    return DAP_respond_dispose(req, 1, body);
  }
  if (strcmp(cmd, "threads") == 0) {
    return DAP_respond_dispose(req, 1, cJSON_CreateRaw("{\"threads\": [{\"id\": 0, \"name\": \"main\"}]}"));
  }
  if (strcmp(cmd, "pause") == 0) {
    dap_wait_reason = "pause";
    dap_wait_on_next_insn_p |= 1;
    return DAP_respond_dispose(req, 1, cJSON_CreateObject());
  }
  if (strcmp(cmd, "setBreakpoints") == 0) {
    /* TODO: set breakpoints */
    cJSON * body = cJSON_CreateObject();
    cJSON_AddArrayToObject(body, "breakpoints");
    return DAP_respond_dispose(req, 1, body);
  }
  if (strcmp(cmd, "source") == 0) {
    /* TODO: Is this correct? */
    cJSON * body = cJSON_CreateObject();
    cJSON_AddStringToObject(body, "content", "");
    return DAP_respond_dispose(req, 1, body);
  }
  if (strcmp(cmd, "initialize") == 0) {
    return DAP_respond_dispose(req, 1, cJSON_CreateObject())
        || DAP_send_output_dispose(DAP_create_event("initialized", NULL));
  }
  if (strcmp(cmd, "launch") == 0) {
    pthread_mutex_unlock(&MUT_LAUNCH);
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
  pthread_mutex_lock(&MUT_LAUNCH);
  static char head_buf[42];
  while (1) {
    int hp = 0;
    while (hp < 16) {
      int n = read(redir[0].fd[2], head_buf + hp, 16 - hp);
      if (n == 0)
        return NULL;
      hp += n;
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
      DAP_output_event("stdout", buffer);
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

void MIR_NO_RETURN DAP_handle_error(enum MIR_error_type error_type, const char *format, ...) {
  va_list ap;
  static char buf[32767];

  va_start(ap, format);
  int x = vsnprintf(buf, 32764, format, ap);
  buf[x] = '\n';
  buf[x + 1] = '\0';
  DAP_output_event("stderr", buf);
  va_end(ap);

  sleep(1000);
  DAP_send_output_dispose(DAP_create_event("terminated", NULL));
  DAP_send_output_dispose(DAP_create_event("exited", cJSON_CreateRaw("{\"exitCode\": 1}")));
  exit(1);
}

int main(int argc, const char ** argv) {
  pthread_t threads[2];
  freopen("mir-intp-dap.log", "a", stderr);
  for (int i = 0; i < MUT_BOUND; i++)
  {
    pthread_mutex_init(mutex + i, NULL);
    pthread_cond_init(cond + i, NULL);
  }
  redir[0] = DAP_redirect(stdin, 0);
  redir[1] = DAP_redirect(stdout, 1);
  pthread_create(threads + 0, NULL, DAP_handle_stdin, NULL);
  pthread_create(threads + 1, NULL, DAP_handle_stdout, NULL);
  MIR_context_t ctx = MIR_init();
  MIR_set_error_func(ctx, DAP_handle_error);
  /* pthread_create(threads + 2, NULL, DAP_handle_stderr, NULL);
  pthread_join(threads[2], NULL); */
  FILE * fp = fopen(argv[argc - 1], "r");
  wait_filepath = argv[argc - 1];
  wait_filename =
    strrchr(wait_filepath, '\\') ? strrchr(wait_filepath, '\\') :
    strrchr(wait_filepath, '/') ? strrchr(wait_filepath, '/') :
    wait_filepath;
  if (fp == NULL) { DAP_handle_error(MIR_binary_io_error, "Cannot open file `%s`\n", argv[argc - 1]); }
  
  fseek(fp, 0, SEEK_END); 
  long size = ftell(fp);
  fseek(fp, 0, SEEK_SET);
  char * scr = malloc(size + 1);
  long n_ch = fread(scr, 1, size, fp);
  fclose(fp);
  scr[n_ch] = '\0';
  
  sleep(200);  /* Should use a semaphore here */
  pthread_mutex_lock(&MUT_LAUNCH);
  pthread_mutex_unlock(&MUT_LAUNCH);
  
  MIR_scan_string(ctx, scr);

  MIR_item_t main_func = NULL;
  for (MIR_module_t module = DLIST_HEAD (MIR_module_t, *MIR_get_module_list (ctx)); module != NULL;
        module = DLIST_NEXT (MIR_module_t, module)) {
    for (MIR_item_t func = DLIST_HEAD (MIR_item_t, module->items); func != NULL;
          func = DLIST_NEXT (MIR_item_t, func))
      if (func->item_type == MIR_func_item && strcmp (func->u.func->name, "main") == 0)
        main_func = func;
    MIR_load_module (ctx, module);
  }
  if (main_func == NULL) { DAP_handle_error(MIR_no_func_error, "No main func found"); }
  DAP_output_event("stdout", "Loaded sucessfully\n");
  MIR_link(ctx, MIR_set_interp_interface, MIR_std_import_resolver);
  DAP_output_event("stdout", "Linked sucessfully\n");
  ((void (*)())(main_func->addr))();

  MIR_finish(ctx);

  sleep(1000);
  DAP_send_output_dispose(DAP_create_event("terminated", NULL));
  DAP_send_output_dispose(DAP_create_event("exited", cJSON_CreateRaw("{\"exitCode\": 0}")));
  return 0;
}
#endif
