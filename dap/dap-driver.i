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
#define _O_BINARY 0x8000
#define pipe(X) _pipe(X, 4096, _O_BINARY)
#define fileno _fileno
#define dup _dup
#define dup2 _dup2
#define close _close
#define read _read
#define write _write
#define sleep Sleep
#endif

typedef struct {
  int fd[3];  /* Read-end, Write-end, Original-fd */
} DAP_redirect_t;

typedef struct {
  MIR_func_t func;
  MIR_val_t * bp;
  int cur_lno;
} DAP_stack_frame_t;

DEF_VARR(DAP_stack_frame_t);

static MIR_context_t dap_main_ctx;
#define MUT_BOUND 10
static pthread_mutex_t mutex[MUT_BOUND];
static pthread_cond_t cond[MUT_BOUND];
static sem_t sem[MUT_BOUND];
static DAP_redirect_t redir[3];  /* STDIN, STDOUT, STDERR (STDERR not redirected now) */
#define MUT_I mutex[0]
#define MUT_O mutex[1]
#define MUT_CA_TRACE mutex[2]
#define COND_CA cond[0]
#define SEM_LAUNCH sem[0]
#define SEM_LAUNCHED sem[1]

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

void MIR_link_no_inline (MIR_context_t ctx, void (*set_interface) (MIR_context_t ctx, MIR_item_t item),
               void *import_resolver (const char *)) {
  MIR_item_t item, tab_item, expr_item;
  MIR_type_t type;
  MIR_val_t res;
  MIR_module_t m;
  void *addr;
  union {
    int8_t i8;
    int16_t i16;
    int32_t i32;
    int64_t i64;
    float f;
    double d;
    long double ld;
    void *a;
  } v;

  for (size_t i = 0; i < VARR_LENGTH (MIR_module_t, modules_to_link); i++) {
    m = VARR_GET (MIR_module_t, modules_to_link, i);
    for (item = DLIST_HEAD (MIR_item_t, m->items); item != NULL;
         item = DLIST_NEXT (MIR_item_t, item))
      if (item->item_type == MIR_func_item) {
        assert (item->data == NULL);
        if (simplify_func (ctx, item, TRUE)) item->data = (void *) 0; /* no inlining */
      } else if (item->item_type == MIR_import_item) {
        if ((tab_item = item_tab_find (ctx, item->u.import_id, &environment_module)) == NULL) {
          if (import_resolver == NULL || (addr = import_resolver (item->u.import_id)) == NULL)
            MIR_get_error_func (ctx) (MIR_undeclared_op_ref_error, "import of undefined item %s",
                                      item->u.import_id);
          MIR_load_external (ctx, item->u.import_id, addr);
          tab_item = item_tab_find (ctx, item->u.import_id, &environment_module);
          mir_assert (tab_item != NULL);
        }
        item->addr = tab_item->addr;
        item->ref_def = tab_item;
      } else if (item->item_type == MIR_export_item) {
        if ((tab_item = item_tab_find (ctx, item->u.export_id, m)) == NULL)
          MIR_get_error_func (ctx) (MIR_undeclared_op_ref_error, "export of undefined item %s",
                                    item->u.export_id);
        item->addr = tab_item->addr;
        item->ref_def = tab_item;
      } else if (item->item_type == MIR_forward_item) {
        if ((tab_item = item_tab_find (ctx, item->u.forward_id, m)) == NULL)
          MIR_get_error_func (ctx) (MIR_undeclared_op_ref_error, "forward of undefined item %s",
                                    item->u.forward_id);
        item->addr = tab_item->addr;
        item->ref_def = tab_item;
      }
  }
  for (size_t i = 0; i < VARR_LENGTH (MIR_module_t, modules_to_link); i++) {
    m = VARR_GET (MIR_module_t, modules_to_link, i);
    for (item = DLIST_HEAD (MIR_item_t, m->items); item != NULL;
         item = DLIST_NEXT (MIR_item_t, item)) {
      if (item->item_type == MIR_func_item && item->data != NULL) {
        process_inlines (ctx, item);
        item->data = NULL;
#if 0
        fprintf (stderr, "+++++ Function after inlining:\n");
        MIR_output_item (ctx, stderr, item);
#endif
      } else if (item->item_type == MIR_ref_data_item) {
        assert (item->u.ref_data->ref_item->addr != NULL);
        addr = (char *) item->u.ref_data->ref_item->addr + item->u.ref_data->disp;
        memcpy (item->u.ref_data->load_addr, &addr, _MIR_type_size (ctx, MIR_T_P));
        continue;
      }
      if (item->item_type != MIR_expr_data_item) continue;
      expr_item = item->u.expr_data->expr_item;
      MIR_interp (ctx, expr_item, &res, 0);
      type = expr_item->u.func->res_types[0];
      switch (type) {
      case MIR_T_I8:
      case MIR_T_U8: v.i8 = (int8_t) res.i; break;
      case MIR_T_I16:
      case MIR_T_U16: v.i16 = (int16_t) res.i; break;
      case MIR_T_I32:
      case MIR_T_U32: v.i32 = (int32_t) res.i; break;
      case MIR_T_I64:
      case MIR_T_U64: v.i64 = (int64_t) res.i; break;
      case MIR_T_F: v.f = res.f; break;
      case MIR_T_D: v.d = res.d; break;
      case MIR_T_LD: v.ld = res.ld; break;
      case MIR_T_P: v.a = res.a; break;
      default: assert (FALSE); break;
      }
      memcpy (item->u.expr_data->load_addr, &v,
              _MIR_type_size (ctx, expr_item->u.func->res_types[0]));
    }
  }
  if (set_interface != NULL) {
    while (VARR_LENGTH (MIR_module_t, modules_to_link) != 0) {
      m = VARR_POP (MIR_module_t, modules_to_link);
      for (item = DLIST_HEAD (MIR_item_t, m->items); item != NULL;
           item = DLIST_NEXT (MIR_item_t, item))
        if (item->item_type == MIR_func_item) {
          finish_func_interpretation (item); /* in case if it was used for expr data */
          set_interface (ctx, item);
        }
    }
    set_interface (ctx, NULL); /* finish interface setting */
  }
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

volatile char dap_wait_on_next_insn_p = 1;
volatile char dap_wait_mode_p = 0;
#define DAP_WAIT_ST_OVER 1
#define DAP_WAIT_ST_OUT 2
/* volatile int wait_line = 1; */
char const * volatile dap_wait_reason = "entry";
char const * volatile wait_filename = "";
char const * volatile wait_filepath = "";
static VARR (DAP_stack_frame_t) * dap_stack_trace;
static void start_insn_trace (MIR_context_t ctx, const char *name, func_desc_t func_desc, code_t pc, size_t nops)
{
  int src_lno = ((MIR_insn_t)pc[1].a)->src_lno;
  char breakpoint_p = ((MIR_insn_t)pc[1].a)->breakpoint_active_p;
  if (src_lno) dap_stack_trace->varr[dap_stack_trace->els_num - 1].cur_lno = src_lno;
  if ((src_lno && dap_wait_on_next_insn_p) || breakpoint_p)
  {
    dap_wait_on_next_insn_p = 0;
    dap_wait_mode_p = 0;
    /* printf("%p %s %d %d\n", ((MIR_insn_t)pc[1].a), name, src_lno, (int)breakpoint_p); */
    cJSON * body = cJSON_CreateObject();
    cJSON_AddStringToObject(body, "reason", breakpoint_p ? "breakpoint" : dap_wait_reason);
    cJSON_AddNumberToObject(body, "threadId", 0);
    DAP_send_output_dispose(DAP_create_event("stopped", body));
    pthread_mutex_lock(&MUT_CA_TRACE);
    pthread_cond_wait(&COND_CA, &MUT_CA_TRACE);
    pthread_mutex_unlock(&MUT_CA_TRACE);
  }
}

static inline void start_eval_trace(MIR_item_t func_item, MIR_val_t * bp) {
  VARR_PUSH(DAP_stack_frame_t, dap_stack_trace, ((DAP_stack_frame_t) {
    func_item->u.func, bp
  }));
}

static inline void end_eval_trace(MIR_item_t func_item, MIR_val_t * bp) {
  VARR_POP(DAP_stack_frame_t, dap_stack_trace);
}

static code_t call_insn_execute (MIR_context_t ctx, code_t pc, MIR_val_t *bp, code_t ops,
                                 int imm_p) {
  static int sttr = 0;
  struct interp_ctx *interp_ctx = ctx->interp_ctx;
  int64_t nops = get_i (ops); /* #args w/o nop, insn, and ff interface address */
  MIR_insn_t insn = get_a (ops + 1);
  MIR_item_t proto_item = get_a (ops + 3);
  void *func_addr = imm_p ? get_a (ops + 4) : *get_aop (bp, ops + 4);
  size_t start = proto_item->u.proto->nres + 5;

  if (VARR_EXPAND (MIR_val_t, arg_vals_varr, nops)) arg_vals = VARR_ADDR (MIR_val_t, arg_vals_varr);

  for (size_t i = start; i < nops + 3; i++) arg_vals[i - start] = bp[get_i (ops + i)];

  char mode = dap_wait_mode_p;
  if ((mode & DAP_WAIT_ST_OVER) && dap_wait_on_next_insn_p)
  {
    dap_wait_on_next_insn_p = 0;
    call (ctx, bp, &insn->ops[proto_item->u.proto->nres + 2] /* arg ops */,
          ops + 2 /* ffi address holder */, proto_item, func_addr, ops + 5 /* results start */,
          nops - start + 3 /* arg # */);
    ++dap_wait_on_next_insn_p;
  }
  else
    call (ctx, bp, &insn->ops[proto_item->u.proto->nres + 2] /* arg ops */,
          ops + 2 /* ffi address holder */, proto_item, func_addr, ops + 5 /* results start */,
          nops - start + 3 /* arg # */);
  if (!(mode & DAP_WAIT_ST_OUT) && (dap_wait_mode_p & DAP_WAIT_ST_OUT))
    ++dap_wait_on_next_insn_p;
  pc += nops + 3; /* nops itself, the call insn, add ff interface address */
  return pc;
}

typedef enum {
  DAP_STR = MIR_T_BOUND + 3,
  DAP_DATABLOCK
} DAP_extended_type_t;

static char const * DAP_pretty_print(MIR_val_t val, long reg_type) {
  static char buffer[512];
  cJSON* str_obj;
  char* str_print;
  switch (reg_type)
  {
  case MIR_T_I8:
  case MIR_T_I16:
  case MIR_T_I32:
  case MIR_T_I64:
    snprintf(buffer, 511, "%" PRId64 " (0x%" PRIx64 ")", val.i, val.u);
    break;
  case MIR_T_U8:
  case MIR_T_U16:
  case MIR_T_U32:
  case MIR_T_U64:
    snprintf(buffer, 511, "%" PRIu64 " (0x%" PRIx64 ")", val.u, val.u);
    break;
  case MIR_T_P:
    snprintf(buffer, 511, "* %" PRIu64 " (0x%" PRIx64 ")", (uint64_t)val.a, (uint64_t)val.a);
    break;
  case MIR_T_F:
    snprintf(buffer, 511, "%lff", (double)val.f);
    break;
  case MIR_T_D:
    snprintf(buffer, 511, "%lf", (double)val.d);
    break;
  case MIR_T_LD:
    snprintf(buffer, 511, "%lf", (double)val.ld);
    break;
  case DAP_STR:
    str_obj = cJSON_CreateStringReference(val.a);
    cJSON_PrintPreallocated (str_obj, buffer, 506, 0);
    cJSON_Delete(str_obj);
    break;
  case DAP_DATABLOCK:
    /* TODO: Refactor and implement */
  default:
    snprintf(buffer, 511, "(T: %d) %p", reg_type, val.a);
    break;
  }
  return buffer;
}

static void DAP_eval_internal(char const * input_str, VARR (char) * out_buf, int dollar);

static MIR_val_t * DAP_eval_find_reg(char const * name) {
  int nFrames = VARR_LENGTH(DAP_stack_frame_t, dap_stack_trace);
  for (int i = nFrames - 1; i >= 0; i--) {
    DAP_stack_frame_t dap_frame = VARR_GET(DAP_stack_frame_t, dap_stack_trace, i);
    reg_desc_t * reg_desc = find_rd_by_name(dap_main_ctx, name, dap_frame.func);
    if (reg_desc) return dap_frame.bp + reg_desc->reg;
  }
  return NULL;
}

static MIR_type_t DAP_eval_type(char const * name) {
  MIR_val_t val;
  int pos = 0;
  int slen = strlen(name);
  if (strcmp(name, "$") == 0) return MIR_T_I16;
  if (sscanf(name, "0x%" SCNx64, &val.i) == 1) return MIR_T_I64;
  if (sscanf(name, "%" SCNi64 "%n", &val.i, &pos) == 1 && pos == slen) return MIR_T_I64;
  if (sscanf(name, "%lff%n", &val.d, &pos) == 1 && pos == slen) { return MIR_T_F; }
  if (sscanf(name, "%lf", &val.d) == 1) return MIR_T_D;
  int nFrames = VARR_LENGTH(DAP_stack_frame_t, dap_stack_trace);
  for (int i = nFrames - 1; i >= 0; i--) {
    DAP_stack_frame_t dap_frame = VARR_GET(DAP_stack_frame_t, dap_stack_trace, i);
    reg_desc_t * reg_desc = find_rd_by_name(dap_main_ctx, name, dap_frame.func);
    if (reg_desc) return reg_desc->type;
    MIR_item_t item;
    for (item = DLIST_HEAD (MIR_item_t, dap_frame.func->func_item->module->items); item != NULL;
         item = DLIST_NEXT (MIR_item_t, item)) {
      if (item->item_type == MIR_import_item || item->item_type == MIR_export_item) {
        if (item->u.export_id && strcmp(item->u.export_id, name) == 0)
          break;
      }
      if (item->item_type == MIR_data_item) {
        if (item->u.data->name && strcmp(item->u.data->name, name) == 0)
          break;
      }
    }
    if (item) {
      if (item->item_type == MIR_import_item || item->item_type == MIR_export_item)
        return MIR_T_P;
      if (item->item_type == MIR_data_item)
        return (item->u.data->el_type == MIR_T_U8 && item->u.data->u.els[item->u.data->nel - 1] == '\0') ? DAP_STR
        : DAP_DATABLOCK;
    }
  }
  return MIR_T_UNDEF;
}

static MIR_val_t DAP_eval_name(char const * name, int dollar) {
  MIR_val_t val;
  val.i = 0;
  int pos = 0;
  int slen = strlen(name);
  if (*name == '*')
    return *(MIR_val_t *)(DAP_eval_name(name + 1, dollar).a);
  if (strcmp(name, "$") == 0) {
    val.i = dollar;
    return val;
  }
  if (sscanf(name, "0x%" SCNx64, &val.i) == 1) return val;
  if (sscanf(name, "%" SCNi64 "%n", &val.i, &pos) == 1 && pos == slen) return val;
  if (sscanf(name, "%lff%n", &val.d, &pos) == 1 && pos == slen) { val.f = (float)val.d; return val; }
  if (sscanf(name, "%lf", &val.d) == 1) return val;
  MIR_val_t * pval = DAP_eval_find_reg(name);
  if (pval != NULL) return *pval;
  int nFrames = VARR_LENGTH(DAP_stack_frame_t, dap_stack_trace);
  for (int i = nFrames - 1; i >= 0; i--) {
    DAP_stack_frame_t dap_frame = VARR_GET(DAP_stack_frame_t, dap_stack_trace, i);
    MIR_item_t item;
    /* FIXME: Refactor me */
    for (item = DLIST_HEAD (MIR_item_t, dap_frame.func->func_item->module->items); item != NULL;
         item = DLIST_NEXT (MIR_item_t, item)) {
      if (item->item_type == MIR_import_item || item->item_type == MIR_export_item) {
        if (item->u.export_id && strcmp(item->u.export_id, name) == 0)
          break;
      }
      if (item->item_type == MIR_data_item) {
        if (item->u.data->name && strcmp(item->u.data->name, name) == 0)
          break;
      }
    }
    while (item) {
      if (item->item_type == MIR_export_item) {
        item = item->ref_def;
        continue;
      }
      else if (item->item_type == MIR_import_item || item->item_type == MIR_func_item) {
        val.a = item->addr;
        return val;
      }
      else if (item->item_type == MIR_data_item) {
        val.a = item->u.data->u.els;
        return val;
      }
      else break;
    }
  }
  return val;
}

static void DAP_eval_dispatch_p(char const * input_str, VARR (char) * out_str, int dollar) {
  char type_s[9];
  char var_s[256];
  int pos;
  MIR_val_t val;
  val.i = 0;
  if (sscanf(input_str, "%8s%n", type_s, &pos) != 1) {
    VARR_PUSH_ARR(char, out_str, "Missing type for p\n", strlen("Missing type for p\n"));
    input_str += pos;
    return;
  }
  if (sscanf(input_str, "%255s%n", var_s, &pos) == 1) {
    val = DAP_eval_name(var_s, dollar);
    input_str += pos;
  }
  while (sscanf(input_str, "%255s%n", var_s, &pos) == 1) {
    val.i += DAP_eval_name(var_s, dollar).i;
    input_str += pos;
  }
  char const * rs = "<?>";
  if (strcmp(type_s, "i8") == 0) {
    val.i = (int8_t)val.i;
    rs = DAP_pretty_print(val, MIR_T_I8);
  }
  else if (strcmp(type_s, "u8") == 0) {
    val.i = (uint8_t)val.i;
    rs = DAP_pretty_print(val, MIR_T_U8);
  }
  else if (strcmp(type_s, "i16") == 0) {
    val.i = (int16_t)val.i;
    rs = DAP_pretty_print(val, MIR_T_I16);
  }
  else if (strcmp(type_s, "u16") == 0) {
    val.i = (uint16_t)val.i;
    rs = DAP_pretty_print(val, MIR_T_U16);
  }
  else if (strcmp(type_s, "i32") == 0) {
    val.i = (int32_t)val.i;
    rs = DAP_pretty_print(val, MIR_T_I32);
  }
  else if (strcmp(type_s, "u32") == 0) {
    val.i = (uint32_t)val.i;
    rs = DAP_pretty_print(val, MIR_T_U32);
  }
  else if (strcmp(type_s, "i64") == 0) {
    val.i = (int64_t)val.i;
    rs = DAP_pretty_print(val, MIR_T_I64);
  }
  else if (strcmp(type_s, "u64") == 0) {
    val.i = (uint64_t)val.i;
    rs = DAP_pretty_print(val, MIR_T_U64);
  }
  else if (strcmp(type_s, "f") == 0) {
    rs = DAP_pretty_print(val, MIR_T_F);
  }
  else if (strcmp(type_s, "d") == 0) {
    rs = DAP_pretty_print(val, MIR_T_D);
  }
  else if (strcmp(type_s, "ld") == 0) {
    rs = DAP_pretty_print(val, MIR_T_LD);
  }
  else if (strcmp(type_s, "str") == 0) {
    rs = DAP_pretty_print(val, DAP_STR);
  }
  VARR_PUSH_ARR(char, out_str, rs, strlen(rs));
  VARR_PUSH(char, out_str, '\n');
}

static void DAP_eval_dispatch_s(char const * input_str, VARR (char) * out_str, int dollar) {
  char target_s[128]; char mov_s[128];
  if (sscanf(input_str, "%127s%127s", target_s, mov_s) != 2)
    VARR_PUSH_ARR(char, out_str, "Wrong nargs for s\n", strlen("Wrong nargs for s\n"));
  else {
    MIR_val_t * target = DAP_eval_find_reg(target_s);
    if (target == NULL)
      VARR_PUSH_ARR(char, out_str, "Invalid target for s\n", strlen("Invalid target for s\n"));
    else
      *target = DAP_eval_name(mov_s, dollar);
  }
}

static void DAP_eval_dispatch_r(char const * input_str, VARR (char) * out_str, int dollar) {
  int s, e, st, pos;
  if (sscanf(input_str, "%d%d%d%n", &s, &e, &st, &pos) != 3) {
    VARR_PUSH_ARR(char, out_str, "Wrong nargs for r\n", strlen("Wrong nargs for r\n"));
  }
  else for (int i = s; i < e; i += st)
    DAP_eval_internal(input_str + pos, out_str, i);
}

static void DAP_eval_internal(char const * input_str, VARR (char) * out_buf, int dollar) {
  while (isspace(*input_str)) ++input_str;
  switch (*input_str) {
    case 'p':
      if (isspace(input_str[1])) {
        DAP_eval_dispatch_p(input_str + 2, out_buf, dollar);
        return;
      }
      break;
    case 's':
      if (isspace(input_str[1])) {
        DAP_eval_dispatch_s(input_str + 2, out_buf, dollar);
        return;
      }
      break;
    case 'r':
      if (isspace(input_str[1])) {
        DAP_eval_dispatch_r(input_str + 2, out_buf, dollar);
        return;
      }
      break;
    case '\0':
      return;
  }
  MIR_type_t ty = DAP_eval_type(input_str);
  if (ty == MIR_T_UNDEF)
    VARR_PUSH_ARR(char, out_buf, "<?>\n", strlen("<?>\n"));
  else {
    MIR_val_t reg = DAP_eval_name(input_str, dollar);
    const char * rs = DAP_pretty_print(reg, ty);
    VARR_PUSH_ARR(char, out_buf, rs, strlen(rs));
    VARR_PUSH(char, out_buf, '\n');
  }
}

char const * DAP_eval(char const * input_str) {
  static VARR (char) * out_buf = NULL;
  if (out_buf == NULL) VARR_CREATE(char, out_buf, 0);
  VARR_TRUNC(char, out_buf, 0);
  DAP_eval_internal(input_str, out_buf, 0);
  if (VARR_LENGTH(char, out_buf) > 0 && VARR_LAST(char, out_buf) == '\n')
    VARR_POP(char, out_buf);
  VARR_PUSH(char, out_buf, '\0');
  return VARR_ADDR(char, out_buf);
}

static int DAP_handle_request(cJSON * req) {
  const char* cmd = cJSON_GetStringValue(cJSON_GetObjectItem(req, "command"));
  char * ret = cJSON_Print(req);
  fprintf(stderr, "> %s\n", ret);
  fflush(stderr);
  cJSON_free(ret);
  if (strcmp(cmd, "next") == 0) {
    pthread_cond_broadcast(&COND_CA);
    dap_wait_reason = "step";
    dap_wait_on_next_insn_p |= 1;
    dap_wait_mode_p = DAP_WAIT_ST_OVER;
    return DAP_respond_dispose(req, 1, cJSON_CreateObject());
  }
  if (strcmp(cmd, "stepIn") == 0) {
    pthread_cond_broadcast(&COND_CA);
    dap_wait_reason = "step";
    dap_wait_on_next_insn_p |= 1;
    dap_wait_mode_p = 0;
    return DAP_respond_dispose(req, 1, cJSON_CreateObject());
  }
  if (strcmp(cmd, "stepOut") == 0) {
    pthread_cond_broadcast(&COND_CA);
    dap_wait_reason = "step";
    dap_wait_mode_p = DAP_WAIT_ST_OUT;
    return DAP_respond_dispose(req, 1, cJSON_CreateObject());
  }
  if (strcmp(cmd, "continue") == 0) {
    pthread_cond_broadcast(&COND_CA);
    return DAP_respond_dispose(req, 1, cJSON_CreateObject());
  }
  if (strcmp(cmd, "evaluate") == 0) {
    cJSON * body = cJSON_CreateObject();
    const char * result = DAP_eval(cJSON_GetStringValue(cJSON_GetObjectItem(cJSON_GetObjectItem(req, "arguments"), "expression")));
    cJSON_AddNumberToObject(body, "variablesReference", 0);
    cJSON_AddStringToObject(body, "result", result);
    return DAP_respond_dispose(req, 1, body);
  }
  if (strcmp(cmd, "variables") == 0) {
    cJSON * body = cJSON_CreateObject();
    cJSON * variables = cJSON_AddArrayToObject(body, "variables");
    cJSON * vid = cJSON_GetObjectItem(cJSON_GetObjectItem(req, "arguments"), "variablesReference");
    DAP_stack_frame_t frame = VARR_GET(
      DAP_stack_frame_t, dap_stack_trace, (int)(cJSON_GetNumberValue(vid) - 1000 + 0.5)
    );
    func_regs_t func_regs = frame.func->internal;
    size_t nlocals = VARR_LENGTH(reg_desc_t, func_regs->reg_descs);
    for (size_t i = 1; i < nlocals; i++) {
      reg_desc_t reg = VARR_GET(reg_desc_t, func_regs->reg_descs, i);
      cJSON * var = cJSON_CreateObject();
      if (!cJSON_AddStringToObject(var, "name", reg.name)) {
        cJSON_Delete(var);
        continue;
      }
      cJSON_AddStringToObject(var, "value", DAP_pretty_print(frame.bp[reg.reg], reg.type));
      cJSON_AddNumberToObject(var, "variablesReference", 0);
      cJSON_AddItemToArray(variables, var);
    }
    return DAP_respond_dispose(req, 1, body);
  }
  if (strcmp(cmd, "scopes") == 0) {
    cJSON * body = cJSON_CreateObject();
    cJSON * scopes = cJSON_AddArrayToObject(body, "scopes");
    cJSON * scope = cJSON_CreateObject();
    cJSON_AddItemToArray(scopes, scope);
    cJSON * sid = cJSON_GetObjectItem(cJSON_GetObjectItem(req, "arguments"), "frameId");
    cJSON_AddItemReferenceToObject(scope, "variablesReference", sid);
    cJSON_AddStringToObject(scope, "name", "Locals");
    cJSON_AddStringToObject(scope, "presentationHint", "locals");
    cJSON_AddFalseToObject(scope, "expensive");
    return DAP_respond_dispose(req, 1, body);
  }
  if (strcmp(cmd, "stackTrace") == 0) {
    cJSON * body = cJSON_CreateObject();
    cJSON * stackFrames = cJSON_AddArrayToObject(body, "stackFrames");
    size_t nFrames = VARR_LENGTH(DAP_stack_frame_t, dap_stack_trace);
    cJSON_AddNumberToObject(body, "totalFrames", nFrames);
    for (size_t i = 0; i < nFrames; i++) {
      cJSON * frame = cJSON_CreateObject();
      DAP_stack_frame_t dap_frame = VARR_GET(DAP_stack_frame_t, dap_stack_trace, i);
      cJSON_InsertItemInArray(stackFrames, 0, frame);
      cJSON_AddNumberToObject(frame, "line", dap_frame.cur_lno);
      cJSON_AddNumberToObject(frame, "column", 0);
      cJSON_AddNumberToObject(frame, "id", 1000 + i);
      cJSON_AddStringToObject(frame, "name", dap_frame.func->name);
      cJSON * src = cJSON_AddObjectToObject(frame, "source");
      cJSON_AddStringToObject(src, "name", wait_filename);
      cJSON_AddStringToObject(src, "path", wait_filepath);
    }
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
    cJSON * body = cJSON_CreateObject();
    cJSON * breaks = cJSON_AddArrayToObject(body, "breakpoints");
    cJSON * lines = cJSON_GetObjectItem(cJSON_GetObjectItem(req, "arguments"), "lines");
    int nlines = cJSON_GetArraySize(lines);
    int * breaks_lno = alloca(sizeof(int) * nlines);
    char * breaks_ver_p = alloca(sizeof(char) * nlines);
    cJSON * bp_lno;
    int i = 0;
    cJSON_ArrayForEach(bp_lno, lines) {
      breaks_ver_p[i] = 0;
      breaks_lno[i++] = cJSON_GetNumberValue(bp_lno) + 0.5;
    }
    for (MIR_module_t module = DLIST_HEAD (MIR_module_t, *MIR_get_module_list (dap_main_ctx)); module != NULL;
         module = DLIST_NEXT (MIR_module_t, module)) {
      for (MIR_item_t func = DLIST_HEAD (MIR_item_t, module->items); func != NULL;
           func = DLIST_NEXT (MIR_item_t, func))
        if (func->item_type == MIR_func_item) {
          for (MIR_insn_t insn = DLIST_HEAD (MIR_insn_t, func->u.func->insns); insn != NULL;
               insn = DLIST_NEXT (MIR_insn_t, insn))
            if (insn->src_lno > 0) {
              insn->breakpoint_active_p = 0;
              for (i = 0; i < nlines; i++) {
                  insn->breakpoint_active_p |= breaks_lno[i] == insn->src_lno;
                  breaks_ver_p[i] |= breaks_lno[i] == insn->src_lno;
              }
            }
        }
    }
    for (i = 0; i < nlines; i++) {
      cJSON * breakpoint = cJSON_CreateObject();
      cJSON_AddBoolToObject(breakpoint, "verified", breaks_ver_p[i]);
      cJSON_AddItemToArray(breaks, breakpoint);
    }
    return DAP_respond_dispose(req, 1, body);
  }
  if (strcmp(cmd, "source") == 0) {
    /* TODO: Is this correct? */
    cJSON * body = cJSON_CreateObject();
    cJSON_AddStringToObject(body, "content", "");
    return DAP_respond_dispose(req, 1, body);
  }
  if (strcmp(cmd, "initialize") == 0) {
    cJSON * caps = cJSON_CreateObject();
    cJSON_AddTrueToObject(caps, "supportsEvaluateForHovers");
    return DAP_respond_dispose(req, 1, caps)
        || DAP_send_output_dispose(DAP_create_event("initialized", NULL));
  }
  if (strcmp(cmd, "launch") == 0) {
    sem_post(&SEM_LAUNCH);
    sem_wait(&SEM_LAUNCHED);
    return DAP_respond_dispose(req, 1, cJSON_CreateObject());
  }
  if (strcmp(cmd, "attach") == 0) {
    return DAP_respond_dispose(req, 1, cJSON_CreateObject());
  }
  if (strcmp(cmd, "disconnect") == 0) {
    close_std_libs();
    close(redir[1].fd[1]);
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
    if (nc == 0) break;
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

int main(int argc, const char ** argv) {
  pthread_t threads[2];
  freopen("mir-intp-dap.log", "a", stderr);
  for (int i = 0; i < MUT_BOUND; i++)
  {
    pthread_mutex_init(mutex + i, NULL);
    pthread_cond_init(cond + i, NULL);
    sem_init(sem + i, 0, 0);
  }
  redir[0] = DAP_redirect(stdin, 0);
  redir[1] = DAP_redirect(stdout, 1);
  pthread_create(threads + 0, NULL, DAP_handle_stdin, NULL);
  pthread_create(threads + 1, NULL, DAP_handle_stdout, NULL);
  MIR_context_t ctx = dap_main_ctx = MIR_init();
  MIR_set_error_func(ctx, DAP_handle_error);
  VARR_CREATE(DAP_stack_frame_t, dap_stack_trace, 0);
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
  
  MIR_scan_string(ctx, scr);
  
  sem_wait(&SEM_LAUNCH);

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
  MIR_link_no_inline(ctx, MIR_set_interp_interface, MIR_std_import_resolver);
  DAP_output_event("stdout", "Linked sucessfully\n");

  sem_post(&SEM_LAUNCHED);

  ((void (*)())(main_func->addr))();

  VARR_DESTROY(DAP_stack_frame_t, dap_stack_trace);
  MIR_finish(ctx);
  DAP_send_output_dispose(DAP_create_event("terminated", NULL));

  close(redir[0].fd[2]);
  close(redir[1].fd[1]);
  pthread_join(threads[0], NULL);
  pthread_join(threads[1], NULL);
  DAP_send_output_dispose(DAP_create_event("exited", cJSON_CreateRaw("{\"exitCode\": 0}")));
  return 0;
}
#endif
