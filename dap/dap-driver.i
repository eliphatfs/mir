#if MIR_DAP
#undef strings
#include "cJSON.h"
#include <stdio.h>

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

int main() {
  return 0;
}
#endif
