#include <stdlib.h>

#define MAX_BUF 10000

int main(int argc, char *argv[]) {
  char cmd[MAX_BUF];

  strcpy(cmd, "/bin/bash -c \"./vulnerable ");
  strcat(cmd, argv[1]);
  strcat(cmd, " < attack_script.sh\"");
  printf("%s\n", cmd);
  int ret = system(cmd);
  printf("Called vulnerable program. Status code: %d\n", ret);
}
