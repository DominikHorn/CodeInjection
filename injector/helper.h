// string helper
char* getLastPathComponent(char* path);

// ptrace helpers
void ptrace_cont(pid_t pid);
void ptrace_attach(pid_t pid);
void ptrace_detach(pid_t pid);
void ptrace_kill_on_parent_exit(pid_t pid);

// changing other process
void* read_data(pid_t pid, unsigned long addr, void *vptr, int len);
char* read_str(int pid, unsigned long addr, int len);
void write_data(pid_t pid, unsigned long addr, void *vptr, int len);

// symbol resolving
struct link_map* locate_linkmap(int pid);
void resolv_tables(int pid, struct link_map* map);
unsigned long find_sym_in_tables(int pid, struct link_map* map, char* sym_name);

// addr resolving to defeat aslr should it be present
unsigned long find_library(const char* library, pid_t pid);
unsigned long find_libc_function(const char* func_name);
unsigned long find_remote_function(const char* library, unsigned long local_addr, pid_t remote_pid);


