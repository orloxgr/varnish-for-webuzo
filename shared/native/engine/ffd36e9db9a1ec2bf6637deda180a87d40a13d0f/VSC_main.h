/*
 * NB:  This file is machine generated, DO NOT EDIT!
 *
 * Edit main.vsc and run lib/libvsc/vsctool.py instead.
 */

struct VSC_main {
	uint64_t	summs;					/* wrk */
	uint64_t	uptime;
	uint64_t	sess_conn;				/* wrk */
	uint64_t	sess_fail;				/* wrk */
	uint64_t	sess_fail_econnaborted;			/* wrk */
	uint64_t	sess_fail_eintr;			/* wrk */
	uint64_t	sess_fail_emfile;			/* wrk */
	uint64_t	sess_fail_ebadf;			/* wrk */
	uint64_t	sess_fail_enomem;			/* wrk */
	uint64_t	sess_fail_other;			/* wrk */
	uint64_t	client_req_400;				/* wrk */
	uint64_t	client_req_417;				/* wrk */
	uint64_t	client_req;				/* wrk */
	uint64_t	esi_req;				/* wrk */
	uint64_t	cache_hit;				/* wrk */
	uint64_t	cache_hit_grace;			/* wrk */
	uint64_t	cache_hitpass;				/* wrk */
	uint64_t	cache_hitmiss;				/* wrk */
	uint64_t	cache_miss;				/* wrk */
	uint64_t	beresp_uncacheable;			/* wrk */
	uint64_t	beresp_shortlived;			/* wrk */
	uint64_t	backend_conn;
	uint64_t	backend_unhealthy;
	uint64_t	backend_busy;
	uint64_t	backend_fail;
	uint64_t	backend_reuse;
	uint64_t	backend_recycle;
	uint64_t	backend_retry;
	uint64_t	backend_wait;
	uint64_t	backend_wait_fail;
	uint64_t	backend_closed;				/* wrk */
	uint64_t	backend_closed_err;
	uint64_t	bc_rem_close;
	uint64_t	bc_req_close;
	uint64_t	bc_req_http10;
	uint64_t	bc_rx_bad;
	uint64_t	bc_rx_body;
	uint64_t	bc_rx_junk;
	uint64_t	bc_rx_overflow;
	uint64_t	bc_rx_timeout;
	uint64_t	bc_tx_proxy;
	uint64_t	bc_tx_pipe;
	uint64_t	bc_tx_error;
	uint64_t	bc_tx_eof;
	uint64_t	bc_resp_close;
	uint64_t	bc_overload;
	uint64_t	fetch_head;				/* wrk */
	uint64_t	fetch_length;				/* wrk */
	uint64_t	fetch_chunked;				/* wrk */
	uint64_t	fetch_eof;				/* wrk */
	uint64_t	fetch_bad;				/* wrk */
	uint64_t	fetch_none;				/* wrk */
	uint64_t	fetch_1xx;				/* wrk */
	uint64_t	fetch_204;				/* wrk */
	uint64_t	fetch_304;				/* wrk */
	uint64_t	fetch_failed;				/* wrk */
	uint64_t	bgfetch_no_thread;			/* wrk */
	uint64_t	pools;
	uint64_t	threads;
	uint64_t	threads_limited;
	uint64_t	threads_created;
	uint64_t	threads_destroyed;
	uint64_t	threads_failed;
	uint64_t	thread_queue_len;
	uint64_t	busy_sleep;				/* wrk */
	uint64_t	busy_wakeup;				/* wrk */
	uint64_t	busy_killed;
	uint64_t	sess_queued;				/* pool */
	uint64_t	sess_dropped;				/* pool */
	uint64_t	req_dropped;				/* pool */
	uint64_t	req_reset;				/* wrk */
	uint64_t	n_object;				/* wrk */
	uint64_t	n_vampireobject;			/* wrk */
	uint64_t	n_objectcore;				/* wrk */
	uint64_t	n_objecthead;				/* wrk */
	uint64_t	n_backend;
	uint64_t	n_expired;
	uint64_t	n_superseded;
	uint64_t	n_lru_nuked;
	uint64_t	n_lru_moved;
	uint64_t	n_lru_limited;
	uint64_t	losthdr;
	uint64_t	s_sess;					/* wrk */
	uint64_t	n_pipe;
	uint64_t	pipe_limited;				/* wrk */
	uint64_t	s_pipe;					/* wrk */
	uint64_t	s_pass;					/* wrk */
	uint64_t	s_fetch;				/* wrk */
	uint64_t	s_bgfetch;				/* wrk */
	uint64_t	s_synth;				/* wrk */
	uint64_t	s_req_hdrbytes;				/* wrk */
	uint64_t	s_req_bodybytes;			/* wrk */
	uint64_t	s_resp_hdrbytes;			/* wrk */
	uint64_t	s_resp_bodybytes;			/* wrk */
	uint64_t	s_pipe_hdrbytes;			/* wrk */
	uint64_t	s_pipe_in;				/* wrk */
	uint64_t	s_pipe_out;				/* wrk */
	uint64_t	transit_stored;				/* wrk */
	uint64_t	transit_buffered;			/* wrk */
	uint64_t	sess_closed;				/* wrk */
	uint64_t	sess_closed_err;
	uint64_t	sess_readahead;				/* wrk */
	uint64_t	sess_herd;				/* wrk */
	uint64_t	sc_rem_close;
	uint64_t	sc_req_close;
	uint64_t	sc_req_http10;
	uint64_t	sc_rx_bad;
	uint64_t	sc_rx_body;
	uint64_t	sc_rx_junk;
	uint64_t	sc_rx_overflow;
	uint64_t	sc_rx_timeout;
	uint64_t	sc_rx_close_idle;
	uint64_t	sc_tx_pipe;
	uint64_t	sc_tx_error;
	uint64_t	sc_tx_eof;
	uint64_t	sc_resp_close;
	uint64_t	sc_overload;
	uint64_t	sc_pipe_overflow;
	uint64_t	sc_range_short;
	uint64_t	sc_req_http20;
	uint64_t	sc_vcl_failure;
	uint64_t	sc_rapid_reset;
	uint64_t	sc_bankrupt;
	uint64_t	client_resp_500;			/* wrk */
	uint64_t	ws_backend_overflow;			/* wrk */
	uint64_t	ws_client_overflow;			/* wrk */
	uint64_t	ws_thread_overflow;			/* wrk */
	uint64_t	ws_session_overflow;
	uint64_t	shm_records;
	uint64_t	shm_writes;
	uint64_t	shm_flushes;
	uint64_t	shm_cont;
	uint64_t	shm_cycles;
	uint64_t	shm_bytes;
	uint64_t	backend_req;
	uint64_t	n_vcl;
	uint64_t	n_vcl_avail;
	uint64_t	n_vcl_discard;
	uint64_t	vcl_fail;				/* wrk */
	uint64_t	bans;					/* ban_mtx */
	uint64_t	bans_completed;				/* ban_mtx */
	uint64_t	bans_obj;				/* ban_mtx */
	uint64_t	bans_req;				/* ban_mtx */
	uint64_t	bans_added;				/* ban_mtx */
	uint64_t	bans_deleted;				/* ban_mtx */
	uint64_t	bans_tested;				/* ban_mtx */
	uint64_t	bans_obj_killed;			/* ban_mtx */
	uint64_t	bans_lurker_tested;			/* ban_mtx */
	uint64_t	bans_tests_tested;			/* ban_mtx */
	uint64_t	bans_lurker_tests_tested;		/* ban_mtx */
	uint64_t	bans_lurker_obj_killed;			/* ban_mtx */
	uint64_t	bans_lurker_obj_killed_cutoff;		/* ban_mtx */
	uint64_t	bans_dups;				/* ban_mtx */
	uint64_t	bans_lurker_contention;			/* ban_mtx */
	uint64_t	bans_persisted_bytes;			/* ban_mtx */
	uint64_t	bans_persisted_fragmentation;		/* ban_mtx */
	uint64_t	n_purges;
	uint64_t	n_obj_purged;
	uint64_t	exp_mailed;
	uint64_t	exp_received;
	uint64_t	hcb_nolock;				/* wrk */
	uint64_t	hcb_lock;
	uint64_t	hcb_insert;
	uint64_t	esi_errors;
	uint64_t	esi_warnings;
	uint64_t	vmods;
	uint64_t	n_gzip;
	uint64_t	n_gunzip;
	uint64_t	n_test_gunzip;
	uint64_t	http1_iovs_flush;
	uint64_t	http1_absolute_form;
};

struct VSC_main_ban_mtx {
	uint64_t	bans;
	uint64_t	bans_completed;
	uint64_t	bans_obj;
	uint64_t	bans_req;
	uint64_t	bans_added;
	uint64_t	bans_deleted;
	uint64_t	bans_tested;
	uint64_t	bans_obj_killed;
	uint64_t	bans_lurker_tested;
	uint64_t	bans_tests_tested;
	uint64_t	bans_lurker_tests_tested;
	uint64_t	bans_lurker_obj_killed;
	uint64_t	bans_lurker_obj_killed_cutoff;
	uint64_t	bans_dups;
	uint64_t	bans_lurker_contention;
	uint64_t	bans_persisted_bytes;
	uint64_t	bans_persisted_fragmentation;
};

struct VSC_main_pool {
	uint64_t	sess_queued;
	uint64_t	sess_dropped;
	uint64_t	req_dropped;
};

struct VSC_main_wrk {
	uint64_t	summs;
	uint64_t	sess_conn;
	uint64_t	sess_fail;
	uint64_t	sess_fail_econnaborted;
	uint64_t	sess_fail_eintr;
	uint64_t	sess_fail_emfile;
	uint64_t	sess_fail_ebadf;
	uint64_t	sess_fail_enomem;
	uint64_t	sess_fail_other;
	uint64_t	client_req_400;
	uint64_t	client_req_417;
	uint64_t	client_req;
	uint64_t	esi_req;
	uint64_t	cache_hit;
	uint64_t	cache_hit_grace;
	uint64_t	cache_hitpass;
	uint64_t	cache_hitmiss;
	uint64_t	cache_miss;
	uint64_t	beresp_uncacheable;
	uint64_t	beresp_shortlived;
	uint64_t	backend_closed;
	uint64_t	fetch_head;
	uint64_t	fetch_length;
	uint64_t	fetch_chunked;
	uint64_t	fetch_eof;
	uint64_t	fetch_bad;
	uint64_t	fetch_none;
	uint64_t	fetch_1xx;
	uint64_t	fetch_204;
	uint64_t	fetch_304;
	uint64_t	fetch_failed;
	uint64_t	bgfetch_no_thread;
	uint64_t	busy_sleep;
	uint64_t	busy_wakeup;
	uint64_t	req_reset;
	uint64_t	n_object;
	uint64_t	n_vampireobject;
	uint64_t	n_objectcore;
	uint64_t	n_objecthead;
	uint64_t	s_sess;
	uint64_t	pipe_limited;
	uint64_t	s_pipe;
	uint64_t	s_pass;
	uint64_t	s_fetch;
	uint64_t	s_bgfetch;
	uint64_t	s_synth;
	uint64_t	s_req_hdrbytes;
	uint64_t	s_req_bodybytes;
	uint64_t	s_resp_hdrbytes;
	uint64_t	s_resp_bodybytes;
	uint64_t	s_pipe_hdrbytes;
	uint64_t	s_pipe_in;
	uint64_t	s_pipe_out;
	uint64_t	transit_stored;
	uint64_t	transit_buffered;
	uint64_t	sess_closed;
	uint64_t	sess_readahead;
	uint64_t	sess_herd;
	uint64_t	client_resp_500;
	uint64_t	ws_backend_overflow;
	uint64_t	ws_client_overflow;
	uint64_t	ws_thread_overflow;
	uint64_t	vcl_fail;
	uint64_t	hcb_nolock;
};

#define VSC_main_size PRNDUP(sizeof(struct VSC_main))

struct vsmw_cluster;
struct vsc_seg;

struct VSC_main *VSC_main_New(struct vsmw_cluster *,
    struct vsc_seg **, const char *fmt, ...);
void VSC_main_Destroy(struct vsc_seg **);
void VSC_main_Summ_wrk_wrk(struct VSC_main_wrk *, const struct VSC_main_wrk *);
void VSC_main_Summ_wrk(struct VSC_main *, const struct VSC_main_wrk *);
void VSC_main_Summ_pool(struct VSC_main *, const struct VSC_main_pool *);
