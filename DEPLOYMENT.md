# Live capture in Coolify without Compose

The host capture helper is a small shell script supervised by systemd. `tshark` does all packet capture and decoding; the helper only starts it and writes its continuous pcapng stream to a FIFO. The service receives `CAP_NET_RAW` and runs in the host network namespace. The backend remains a normal Coolify Dockerfile application.

## Install the host capture package

Build the Debian package from the repository:

```sh
./host-capture/build-deb.sh
```

Copy `/tmp/traffic-guardian-host-capture_1.0.0_all.deb` to the Coolify server and install it:

```sh
sudo apt install ./traffic-guardian-host-capture_1.0.0_all.deb
```

The package installs `tshark` as a dependency, creates `/var/lib/traffic-guardian/traffic.pcapng` as a FIFO, and starts `traffic-guardian-host-capture.service`. It captures `any` by default. To narrow capture to one host interface, edit `/etc/default/traffic-guardian-host-capture` and set `CAPTURE_INTERFACE=eth0`, then restart the service.

## Connect the normal backend app

In the Coolify backend application's **Persistent Storage**, add a bind mount:

- Host path: `/var/lib/traffic-guardian`
- Container path: `/capture`
- Read/write: enabled

Set this application environment variable:

```text
CAPTURE_PIPE=/capture/traffic.pcapng
```

Redeploy the backend. Keep the frontend API domain and ordinary Dockerfile deployment unchanged.

The Coolify app and host capture service must run on the same server. `any` sees packets on all interfaces visible to that host; packets may be counted more than once if they cross multiple interfaces. Traffic exchanged only between other machines on a switch is not visible unless the network sends a mirrored copy to this server.

Manage the host service with `systemctl status traffic-guardian-host-capture` and `journalctl -u traffic-guardian-host-capture -f`.
