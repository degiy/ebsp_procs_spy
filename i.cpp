// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "i.h"
#include "i.skel.h"
#include <string>
#include <vector>
#include <unordered_set>
#include <unordered_map>
#include <arpa/inet.h>

using namespace std;
using StringId = uint16_t;

vector<const string*> vec_strings;
unordered_map<string, StringId> map_strings;
StringId cp_strings=0;

class Process
{
    public:
    StringId name;
    unordered_set<StringId> set_files;
};

unordered_map<pid_t, Process> map_process;

static struct env {
	bool verbose;
	uid_t uid;
} env;

const char *argp_program_version = "i 0.0";
const char *argp_program_bug_address = "<degiy@yahoo.fr>";
const char argp_program_doc[] =                                         \
    "BPF app to get all open files and network cnx from all process belonging to a specific user\n"
    "It traces process start and exits, find if they match uid, if yes :\n"
    "- log open files\n"
    "- log udp msg send/received\n"
    "- log tcp cnx made to and received from\n"
    "USAGE: ./i [-u uid] [-v]\n";

static const struct argp_option opts[] = {
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ "uid", 'u', "UID", 0, "uid to get process from" },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'v':
		env.verbose = true;
		break;
	case 'u':
		errno = 0;
		env.uid = strtol(arg, NULL, 0);
		if (errno || env.uid < 0) {
			fprintf(stderr, "Invalid uid: %s\n", arg);
			argp_usage(state);
		}
		break;
	case ARGP_KEY_ARG:
		argp_usage(state);
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static const struct argp argp = {
	.options = opts,
	.parser = parse_arg,
	.doc = argp_program_doc,
};

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static volatile bool exiting = false;

static void sig_handler(int sig)
{
    if (env.verbose) printf("signal catched, closing opened pids\n");
	exiting = true;
}

void output_stats_process(pid_t pid)
{
    auto it = map_process.find(pid);
    if (it == map_process.end())
        return;
    const string *pstr;
    try { pstr=vec_strings.at(it->second.name); }
    catch(...) { return;}
    printf("process : %s (pid=%d) :\n",pstr->c_str(),pid);
    
    Process& p = it->second;
    for (const auto& id : p.set_files)
    {
        try { pstr=vec_strings.at(id); }
        catch(...) { continue;}
        printf("  - file : %s\n",pstr->c_str());
    }
}

void close_process()
{
    if (env.verbose) printf("processing remaining open process\n");
    for (auto const& [pid, _] : map_process)
    {
        output_stats_process(pid);
    }
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct event *e = static_cast<const struct event *>(data);
	struct tm *tm;
	char ts[32];
	time_t t;

	time(&t);
	tm = localtime(&t);
	strftime(ts, sizeof(ts), "%H:%M:%S", tm);

    switch (e->type)
    {
        case NEW_PROC:
        {
            if (env.verbose) printf("[%s] new proc : pid=%d, exe=%s\n",ts,e->pid,e->txt);
            auto [it, inserted] = map_strings.emplace(e->txt, cp_strings);
            if (env.verbose) printf("proc inserted=%d\n",inserted);
            if (inserted)
            {
                vec_strings.push_back(&(it->first));
                ++cp_strings;
                if (env.verbose) printf ("  new string cp=%d\n",cp_strings);
            }
            StringId id_s = it->second;
            Process np{.name=id_s};
            map_process.emplace(e->pid,move(np));
            break;
        }
        case FIN_PROC:
        {
            if (env.verbose) printf("[%s] end proc : pid=%d\n",ts,e->pid);
            output_stats_process(e->pid);
            map_process.erase(e->pid);
            break;
        }
        case FILE_OPEN:
        {
            if (env.verbose) printf("[%s] pid=%d opens %s\n",ts,e->pid,e->txt);
            auto [it, inserted] = map_strings.emplace(e->txt, cp_strings);
            if (env.verbose) printf("file inserted=%d\n",inserted);
            if (inserted)
            {
                vec_strings.push_back(&(it->first));
                ++cp_strings;
                if (env.verbose) printf ("  new string cp=%d\n",cp_strings);
            }
            StringId id_s = it->second;
            auto itp = map_process.find(e->pid);
            if (itp == map_process.end())
                break;
            itp->second.set_files.emplace(id_s);
            break;
        }
        case UDP_SND:
        {
            if (env.verbose)
            {
                __u32 dstip=e->ip.dstip;
                __u8 *p=(__u8*)&dstip;
                
                printf("[%s] pid=%d UDP SND to %d.%d.%d.%d port %d\n",ts,e->pid, \
                       p[0],p[1],p[2],p[3],ntohs(e->ip.dstport));
            }
            break;
        }
        case UDP_RCV:
        {
            if (env.verbose)
            {
                __u32 srcip=e->ip.srcip;
                __u8 *p=(__u8*)&srcip;
                
                printf("[%s] pid=%d UDP RCV from %d.%d.%d.%d on port %d\n",ts,e->pid, \
                       p[0],p[1],p[2],p[3],ntohs(e->ip.dstport));
            }
            break;
        }
        default:
        {
            break;
        }
    }

	return 0;
}

int main(int argc, char **argv)
{
	struct ring_buffer *rb = NULL;
	struct i_bpf *skel;
	int err;

	/* Parse command line arguments */
	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Cleaner handling of Ctrl-C */
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	/* Load and verify BPF application */
	skel = i_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	/* Parameterize BPF code with minimum duration parameter */
	skel->rodata->ref_uid = env.uid;

	/* Load & verify BPF programs */
	err = i_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	/* Attach tracepoints */
	err = i_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	/* Set up ring buffer polling */
	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
	if (!rb) {
		err = -1;
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup;
	}

	/* Process events */
	if (env.verbose) printf("starting to watch process for uid=%d\n",env.uid);
	while (!exiting) {
		err = ring_buffer__poll(rb, 100 /* timeout, ms */);
		/* Ctrl-C will cause -EINTR */
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			printf("Error polling perf buffer: %d\n", err);
			break;
		}
	}

    close_process();

cleanup:
	/* Clean up */
	ring_buffer__free(rb);
	i_bpf__destroy(skel);

	return err < 0 ? -err : 0;
}
