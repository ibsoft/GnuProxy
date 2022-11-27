from datetime import timedelta
import time
import platform
import socket
import netifaces
from app import app, mysql, MySQLdb, render_template, request, redirect, url_for, session, loggedin, hashlib, os, flash, g
import psutil



class NetIOCounters(object):
    def __init__(self, pernic=True):
        self.last_req = None
        self.last_req_time = None
        self.pernic = pernic

    def _get_net_io_counters(self):
        """
        Fetch io counters from psutil and transform it to
        dicts with the additional attributes defaulted
        """
        counters = psutil.net_io_counters(pernic=self.pernic)

        res = {}
        for name, io in counters.iteritems():
            res[name] = io._asdict()
            res[name].update({'tx_per_sec': 0, 'rx_per_sec': 0})

        return res

    def _set_last_request(self, counters):
        self.last_req = counters
        self.last_req_time = time.time()

    def get(self):
        return self.last_req

    def update(self):
        counters = self._get_net_io_counters()

        if not self.last_req:
            self._set_last_request(counters)
            return counters

        time_delta = time.time() - self.last_req_time
        if not time_delta:
            return counters

        for name, io in counters.iteritems():
            last_io = self.last_req.get(name)
            if not last_io:
                continue

            counters[name].update({
                'rx_per_sec': (io['bytes_recv'] - last_io['bytes_recv']) / time_delta,
                'tx_per_sec': (io['bytes_sent'] - last_io['bytes_sent']) / time_delta
            })

        self._set_last_request(counters)

        return counters


def get_interface_addresses():
    """
    Get addresses of available network interfaces.
    See netifaces on pypi for details.

    Returns a list of dicts
    """

    addresses = []
    ifaces = netifaces.interfaces()
    for iface in ifaces:
        addrs = netifaces.ifaddresses(iface)
        families = addrs.keys()

        # put IPv4 to the end so it lists as the main iface address
        if netifaces.AF_INET in families:
            families.remove(netifaces.AF_INET)
            families.append(netifaces.AF_INET)

        for family in families:
            for addr in addrs[family]:
                address = {
                    'name': iface,
                    'family': family,
                    'ip': addr['addr'],
                }
                addresses.append(address)

    return addresses

#
# Helpers functions start
#
class helpers(object):

    def get_sysinfo(self):
            uptime = int(time.time() - psutil.boot_time())
            sysinfo = {
                'uptime': uptime,
                'hostname': socket.gethostname(),
                'os': platform.platform(),
                'load_avg': psutil.getloadavg(),
                'num_cpus': psutil.cpu_count()
            }
            return sysinfo
        

        
    def get_memory(self):
        return psutil.virtual_memory()._asdict()

    def get_swap_space(self):
        sm = psutil.swap_memory()
        swap = {
            'total': sm.total,
            'free': sm.free,
            'used': sm.used,
            'percent': sm.percent,
            'swapped_in': sm.sin,
            'swapped_out': sm.sout
        }
        return swap

    def get_cpu(self):
        return psutil.cpu_times_percent(0)._asdict()

    def get_cpu_cores(self):
        return [c._asdict() for c in psutil.cpu_times_percent(0, percpu=True)]

    def get_disks(self, all_partitions=False):
        disks = []
        for dp in psutil.disk_partitions(all_partitions):
            usage = psutil.disk_usage(dp.mountpoint)
            disk = {
                'device': dp.device,
                'mountpoint': dp.mountpoint,
                'type': dp.fstype,
                'options': dp.opts,
                'space_total': usage.total,
                'space_used': usage.used,
                'space_used_percent': usage.percent,
                'space_free': usage.free
            }
            disks.append(disk)

        return disks

    def get_disks_counters(self, perdisk=True):
        return dict((dev, c._asdict()) for dev, c in psutil.disk_io_counters(perdisk=perdisk).iteritems())

    def get_users(self):
        return [u._asdict() for u in psutil.users()]


    def get_network_interfaces(self):
        io_counters = NetIOCounters()
        addresses = get_interface_addresses()

        netifs = {}
        for addr in addresses:
            c = io_counters.get(addr['name'])
            if not c:
                continue
            netifs[addr['name']] = {
                'name': addr['name'],
                'ip': addr['ip'],
                'bytes_sent': c['bytes_sent'],
                'bytes_recv': c['bytes_recv'],
                'packets_sent': c['packets_sent'],
                'packets_recv': c['packets_recv'],
                'errors_in': c['errin'],
                'errors_out': c['errout'],
                'dropped_in': c['dropin'],
                'dropped_out': c['dropout'],
                'send_rate': c['tx_per_sec'],
                'recv_rate': c['rx_per_sec']
            }

        return netifs

    def get_process_list(self):
        process_list = []
        for p in psutil.process_iter():
            mem = p.memory_info()
            
            # psutil throws a KeyError when the uid of a process is not associated with an user.
            try:
                username = p.username()
            except KeyError:
                username = None

            proc = {
                'pid': p.pid,
                'name': p.name(),
                'cmdline': ' '.join(p.cmdline()),
                'user': username,
                'status': p.status(),
                'created': p.create_time(),
                'mem_rss': mem.rss,
                'mem_vms': mem.vms,
                'mem_percent': p.memory_percent(),
                'cpu_percent': p.cpu_percent(0)
            }
            process_list.append(proc)

        return process_list

    def get_process(self, pid):
        p = psutil.Process(pid)
        mem = p.memory_info_ex()
        cpu_times = p.cpu_times()

        # psutil throws a KeyError when the uid of a process is not associated with an user.
        try:
            username = p.username()
        except KeyError:
            username = None

        return {
            'pid': p.pid,
            'ppid': p.ppid(),
            'parent_name': p.parent().name() if p.parent() else '',
            'name': p.name(),
            'cmdline': ' '.join(p.cmdline()),
            'user': username,
            'uid_real': p.uids().real,
            'uid_effective': p.uids().effective,
            'uid_saved': p.uids().saved,
            'gid_real': p.gids().real,
            'gid_effective': p.gids().effective,
            'gid_saved': p.gids().saved,
            'status': p.status(),
            'created': p.create_time(),
            'terminal': p.terminal(),
            'mem_rss': mem.rss,
            'mem_vms': mem.vms,
            'mem_shared': mem.shared,
            'mem_text': mem.text,
            'mem_lib': mem.lib,
            'mem_data': mem.data,
            'mem_dirty': mem.dirty,
            'mem_percent': p.memory_percent(),
            'cwd': p.cwd(),
            'nice': p.nice(),
            'io_nice_class': p.ionice()[0],
            'io_nice_value': p.ionice()[1],
            'cpu_percent': p.cpu_percent(0),
            'num_threads': p.num_threads(),
            'num_files': len(p.open_files()),
            'num_children': len(p.children()),
            'num_ctx_switches_invol': p.num_ctx_switches().involuntary,
            'num_ctx_switches_vol': p.num_ctx_switches().voluntary,
            'cpu_times_user': cpu_times.user,
            'cpu_times_system': cpu_times.system,
            'cpu_affinity': p.cpu_affinity()
        }

    def get_process_limits(self, pid):
        p = psutil.Process(pid)
        return {
            'RLIMIT_AS': p.rlimit(psutil.RLIMIT_AS),
            'RLIMIT_CORE': p.rlimit(psutil.RLIMIT_CORE),
            'RLIMIT_CPU': p.rlimit(psutil.RLIMIT_CPU),
            'RLIMIT_DATA': p.rlimit(psutil.RLIMIT_DATA),
            'RLIMIT_FSIZE': p.rlimit(psutil.RLIMIT_FSIZE),
            'RLIMIT_LOCKS': p.rlimit(psutil.RLIMIT_LOCKS),
            'RLIMIT_MEMLOCK': p.rlimit(psutil.RLIMIT_MEMLOCK),
            'RLIMIT_MSGQUEUE': p.rlimit(psutil.RLIMIT_MSGQUEUE),
            'RLIMIT_NICE': p.rlimit(psutil.RLIMIT_NICE),
            'RLIMIT_NOFILE': p.rlimit(psutil.RLIMIT_NOFILE),
            'RLIMIT_NPROC': p.rlimit(psutil.RLIMIT_NPROC),
            'RLIMIT_RSS': p.rlimit(psutil.RLIMIT_RSS),
            'RLIMIT_RTPRIO': p.rlimit(psutil.RLIMIT_RTPRIO),
            'RLIMIT_RTTIME': p.rlimit(psutil.RLIMIT_RTTIME),
            'RLIMIT_SIGPENDING': p.rlimit(psutil.RLIMIT_SIGPENDING),
            'RLIMIT_STACK': p.rlimit(psutil.RLIMIT_STACK)
        }

    def get_process_environment(self, pid):
        with open('/proc/%d/environ' % pid) as f:
            contents = f.read()
            env_vars = dict(row.split('=', 1) for row in contents.split('\0') if '=' in row)
        return env_vars

    def get_process_threads(self, pid):
        threads = []
        proc = psutil.Process(pid)
        for t in proc.threads():
            thread = {
                'id': t.id,
                'cpu_time_user': t.user_time,
                'cpu_time_system': t.system_time,
            }
            threads.append(thread)
        return threads

    def get_process_open_files(self, pid):
        proc = psutil.Process(pid)
        return [f._asdict() for f in proc.open_files()]

   

    def get_process_memory_maps(self, pid):
        return [m._asdict() for m in psutil.Process(pid).memory_maps()]

    def get_process_children(self, pid):
        proc = psutil.Process(pid)
        children = []
        for c in proc.children():
            child = {
                'pid': c.pid,
                'name': c.name(),
                'cmdline': ' '.join(c.cmdline()),
                'status': c.status()
            }
            children.append(child)

        return children

    

    def get_logs(self):
        available_logs = []
        for log in self.node.logs.get_available():
            try:
                stat = os.stat(log.filename)
                available_logs.append({
                    'path': log.filename.encode("utf-8"),
                    'size': stat.st_size,
                    'atime': stat.st_atime,
                    'mtime': stat.st_mtime
                })
            except OSError:
                app.logger.info('Could not stat "%s", removing from available logs', log.filename)
                self.node.logs.remove_available(log.filename)

        return available_logs

    def read_log(self, filename, session_key=None, seek_tail=False):
        log = self.node.logs.get(filename, key=session_key)
        if seek_tail:
            log.set_tail_position()
        return log.read()

    def search_log(self, filename, text, session_key=None):
        log = self.node.logs.get(filename, key=session_key)
        pos, bufferpos, res = log.search(text)
        stat = os.stat(log.filename)
        data = {
            'position': pos,
            'buffer_pos': bufferpos,
            'filesize': stat.st_size,
            'content': res
        }
        return data
