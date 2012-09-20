int cpt_collect_signals(cpt_context_t *);
int cpt_dump_signal(struct cpt_context *);
int cpt_dump_sighand(struct cpt_context *);
int cpt_dump_tasks(struct cpt_context *);

int rst_signal_complete(struct cpt_task_image *ti, int *exiting, struct cpt_context *ctx);
__u32 rst_signal_flag(struct cpt_task_image *ti, struct cpt_context *ctx);

int rst_restore_process(struct cpt_context *ctx);
int rst_process_linkage(struct cpt_context *ctx);

int check_task_state(struct task_struct *tsk, struct cpt_context *ctx);
struct pid *alloc_vpid_safe(pid_t vnr);
int cpt_skip_task(struct task_struct *tsk);
