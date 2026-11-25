INCLUDE PERFETTO MODULE android.binder;

SELECT client_process, client_pid, client_upid, client_ts,
       server_process, server_pid, server_upid, server_ts
FROM android_binder_txns
ORDER BY client_ts;
