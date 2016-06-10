#ifndef _SUCI_H_
#define _SUCI_H_
int do_uci_set(char *option, char *value);
int do_uci_get(char *option, char *value);
int do_uci_add_list(char *option, char *value);
int do_uci_del_list(char *option, char *value);
int do_uci_commit(char *package);
int do_uci_add(char *option, char *section, char *name);
int do_uci_delete(char *option, char *value);
int do_uci_rename(char *option, char *name);
#endif
