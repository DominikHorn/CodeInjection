// string helper
char* getLastPathComponent(char* path);

// ptrace helpers
void ptrace_cont(pid_t pid);
void ptrace_detach(pid_t pid);
void* read_data(pid_t pid, unsigned long addr, void *vptr, int len);
void write_data(pid_t pid, unsigned long addr, void *vptr, int len);
