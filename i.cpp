// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
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
// we only store refs to strings (16 bits only, will need to increase if two much info to fetch)
using StringId = uint16_t;

// we will keep all strings for ever in a vector (only ref) for both open files and process names
vector<const string*> vec_strings;
// the map that old the real strings
unordered_map<string, StringId> map_strings;
// the id of the next index to use in vector to ref the string
StringId cp_strings=0;

#define KD_TCP 2 // bit mask : 1 for TCP / 0 for UDP
#define KD_UDP 0
#define KD_OUT 1 // bit mask : 1 for OUT / 0 for IN
#define KD_IN  0
#define KD_MCAST 4 // just for UDP IN

// Network class 
struct IpPort
{
    __u32 ip;
    __u32 ipm;
    __u16 port;
    __u16 kind;
    bool operator==(const IpPort& o) const noexcept
    {
        return memcmp(this, &o, sizeof(IpPort)) == 0;
    };
};

struct KeyHasher {
    std::size_t operator()(const IpPort& k) const noexcept {
        // 64 bits (ip + ipm)  and 32 bits (port + kind)
        uint64_t p1 = (static_cast<uint64_t>(k.ip) << 32) | k.ipm;
        uint32_t p2 = (static_cast<uint32_t>(k.port) << 16) | k.kind;

        std::size_t h1 = std::hash<uint64_t>{}(p1);
        std::size_t h2 = std::hash<uint32_t>{}(p2);

        // style boost::hash_combine
        return h1 ^ (h2 + 0x9e3779b9 + (h1 << 6) + (h1 >> 2));
    }
};

// how we store process : a ref string for its name, and a set a ref strings for its openfiles + networks access (in an out / udp and tcp)
class Process
{
    public:
    StringId name;
    unordered_set<StringId> set_files;
    unordered_map<IpPort,__u32,KeyHasher> map_net;
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

#define printfd(...) \
    do { \
        if (env.verbose) { \
            printf(__VA_ARGS__); \
        } \
    } while (0)

static volatile bool exiting = false;

static void sig_handler(int sig)
{
    printfd("signal catched, closing opened pids\n");
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

    // create a dir per process
    string dir=*pstr;
    for (char& c : dir) if (c == '/' || c == '.') c = '_';
    dir+=".";
    dir+=to_string(pid);
        
    if (mkdir(dir.c_str(), 0755) == -1 && errno != EEXIST)
    {
        perror("mkdir for process");
        exit(-1);
    }

    // and a file with the real filename (cmd launched)
    string fn=dir+"/name";
    FILE *f = fopen(fn.c_str(), "w");
    if (!f) {
        perror("fopen name of process");
        exit(-1);
    }
    fprintf(f,"%s\n",pstr->c_str());
    fclose(f);
    
    // then all the files open by the process
    fn=dir+"/files.csv";
    f = fopen(fn.c_str(), "a");
    if (!f) {
        perror("fopen list of files");
        exit(-1);
    }
    Process& p = it->second;
    for (const auto& id : p.set_files)
    {
        try { pstr=vec_strings.at(id); }
        catch(...) { continue;}
        fprintf(f,"%s\n",pstr->c_str());
    }
    fclose(f);
    
    // then all the udp/tcp flow received/send by process
    fn=dir+"/udp_in.csv";
    FILE *fui = fopen(fn.c_str(), "a");
    if (!fui) { perror("fopen udp in"); exit(-1); }

    fn=dir+"/udp_mcast_in.csv";
    FILE *fuim = fopen(fn.c_str(), "a");
    if (!fuim) { perror("fopen udp mcast in"); exit(-1); }

    fn=dir+"/udp_out.csv";
    FILE *fuo = fopen(fn.c_str(), "a");
    if (!fuo) { perror("fopen udp out"); exit(-1); }

    fn=dir+"/tcp_in.csv";
    FILE *fti = fopen(fn.c_str(), "a");
    if (!fti) { perror("fopen tcp in"); exit(-1); }

    fn=dir+"/tcp_out.csv";
    FILE *fto = fopen(fn.c_str(), "a");
    if (!fto) { perror("fopen tcp out"); exit(-1); }
    for (const auto& [ad, cp] : p.map_net)
    {
        __u8 *p=(__u8*)&(ad.ip);
        switch (ad.kind)
        {
            case (KD_UDP | KD_IN | KD_MCAST):
            {
                __u8 *pm=(__u8*)&(ad.ipm);
                fprintf(fuim,"%3d.%3d;%3d.%3d;%5d;%3d.%3d.%3d.%3d;%d;\n", \
                        pm[0],pm[1],pm[2],pm[3],ad.port,                \
                        p[0],p[1],p[2],p[3],cp);
                break;
            };
            case (KD_UDP | KD_IN):
            {
                fprintf(fui,"%5d;%3d.%3d.%3d.%3d;%d;\n", \
                       ad.port,p[0],p[1],p[2],p[3],cp);
                break;
            };
            case (KD_UDP | KD_OUT):
            {
                fprintf(fuo,"%3d.%3d.%3d.%3d;%5d;%d;\n", \
                       p[0],p[1],p[2],p[3],ad.port,cp);
                break;
            };
            case (KD_TCP | KD_IN):
            {
                fprintf(fti,"%5d;%3d.%3d.%3d.%3d;%d;\n", \
                       ad.port,p[0],p[1],p[2],p[3],cp);
                break;
            };
            case (KD_TCP | KD_OUT):
            {
                fprintf(fto,"%3d.%3d.%3d.%3d;%5d;%d;\n", \
                       p[0],p[1],p[2],p[3],ad.port,cp);
                break;
            };
            default:
            {
                printf("unknown case in ebpf network kind\n");
                exit(-1);
            }
        }
    }
    fclose(fto);
    fclose(fti);
    fclose(fuo);
    fclose(fuim);
    fclose(fui);
}

void close_process()
{
    printfd("processing remaining open process\n");
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
            printfd("[%s] new proc : pid=%d, exe=%s\n",ts,e->pid,e->txt);
            auto [it, inserted] = map_strings.emplace(e->txt, cp_strings);
            printfd("proc inserted=%d\n",inserted);
            if (inserted)
            {
                vec_strings.push_back(&(it->first));
                ++cp_strings;
                printfd ("  new string cp=%d\n",cp_strings);
            }
            StringId id_s = it->second;
            Process np{.name=id_s};
            map_process.emplace(e->pid,move(np));
            break;
        }
        case FIN_PROC:
        {
            printfd("[%s] end proc : pid=%d\n",ts,e->pid);
            output_stats_process(e->pid);
            map_process.erase(e->pid);
            break;
        }
        case FILE_OPEN:
        {
            printfd("[%s] pid=%d opens %s\n",ts,e->pid,e->txt);
            auto [it, inserted] = map_strings.emplace(e->txt, cp_strings);
            printfd("file inserted=%d\n",inserted);
            if (inserted)
            {
                vec_strings.push_back(&(it->first));
                ++cp_strings;
                printfd ("  new string cp=%d\n",cp_strings);
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
                __u32 ip=e->ip.dstip;
                __u8 *p=(__u8*)&ip;
                
                printf("[%s] pid=%d UDP SND to %d.%d.%d.%d port %d\n",ts,e->pid, \
                       p[0],p[1],p[2],p[3],ntohs(e->ip.dstport));
            }
            auto itp = map_process.find(e->pid);
            if (itp == map_process.end())
                break;
            IpPort ad{e->ip.dstip,0,ntohs(e->ip.dstport),KD_UDP|KD_OUT};
            auto ita = itp->second.map_net.find(ad);
            if (ita != itp->second.map_net.end())
            {
                // address already exist in network map of process, so just add +1
                ita->second++;
            }
            else
            {
                // need to init (first time)
                itp->second.map_net.emplace(move(ad),1);
            }
            break;
            break;
        }
        case UDP_RCV:
        {
            if (env.verbose)
            {
                __u32 ip=e->ip.srcip;
                __u8 *p=(__u8*)&ip;
                
                printf("[%s] pid=%d UDP RCV from %d.%d.%d.%d on port %d\n",ts,e->pid, \
                       p[0],p[1],p[2],p[3],e->ip.dstport);
                if (e->ip.dstip)
                {
                    p=(__u8*)(&e->ip.dstip);
                    printf("     mcast : %d.%d.%d.%d\n", p[0],p[1],p[2],p[3]);
                }
            }
            auto itp = map_process.find(e->pid);
            if (itp == map_process.end())
                break;
            IpPort ad{e->ip.srcip,e->ip.dstip,e->ip.dstport,KD_UDP|KD_IN};
            if (e->ip.dstip) ad.kind|=KD_MCAST;
            auto ita = itp->second.map_net.find(ad);
            if (ita != itp->second.map_net.end())
            {
                // address already exist in network map of process, so just add +1
                ita->second++;
            }
            else
            {
                // need to init (first time)
                itp->second.map_net.emplace(move(ad),1);
            }
            break;
        }
        case TCP_CNX:
        {
            if (env.verbose)
            {
                __u32 ip=e->ip.dstip;
                __u8 *p=(__u8*)&ip;
                
                printf("[%s] pid=%d TCP CNX to %d.%d.%d.%d port %d\n",ts,e->pid, \
                       p[0],p[1],p[2],p[3],ntohs(e->ip.dstport));
            }
            auto itp = map_process.find(e->pid);
            if (itp == map_process.end())
                break;
            IpPort ad{e->ip.dstip,0,ntohs(e->ip.dstport),KD_TCP|KD_OUT};
            auto ita = itp->second.map_net.find(ad);
            if (ita != itp->second.map_net.end())
            {
                // address already exist in network map of process, so just add +1
                ita->second++;
            }
            else
            {
                // need to init (first time)
                itp->second.map_net.emplace(move(ad),1);
            }
            break;
        }
        case TCP_ACC:
        {
            if (env.verbose)
            {
                __u32 ip=e->ip.srcip;
                __u8 *p=(__u8*)&ip;
                
                printf("[%s] pid=%d TCP CNX from %d.%d.%d.%d on port %d\n",ts,e->pid, \
                       p[0],p[1],p[2],p[3],e->ip.dstport);
            }
            auto itp = map_process.find(e->pid);
            if (itp == map_process.end())
                break;
            IpPort ad{e->ip.srcip,0,e->ip.dstport,KD_TCP|KD_IN};
            auto ita = itp->second.map_net.find(ad);
            if (ita != itp->second.map_net.end())
            {
                // address already exist in network map of process, so just add +1
                ita->second++;
            }
            else
            {
                // need to init (first time)
                itp->second.map_net.emplace(move(ad),1);
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
	printfd("starting to watch process for uid=%d\n",env.uid);
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
