//! Container escapes, through the entry point an agent's command goes through.
//!
//! Measured on the released guard (1.6.12) on 2026-11-12: a container started
//! with full privilege or in the host's process namespace, `nsenter` into PID
//! 1, and the container runtime's API called with `curl` on its socket were all
//! answered "no rule matched". The one container rule there was (the host root
//! mounted with `-v`) matched a single spelling under three target names.
//!
//! The lists here are the measured lines plus the other spellings of each. The
//! per-rule wording is pinned in the unit tests of `threats.rs`; what is pinned
//! here is the verdict an agent receives.

use innerwarden_agent_guard::mcp::{analyze_command, blocks_for_agent};

#[test]
fn a_container_escape_is_refused() {
    for cmd in [
        "docker run --rm --privileged alpine sh",
        "docker run --rm --privileged=true alpine sh",
        "docker run --rm --privileged=\"true\" alpine sh",
        "docker run --rm --privileged=$P alpine sh",
        "docker run -e A='x;y' --privileged alpine sh",
        "docker --config '/tmp/a;b' run --privileged alpine sh",
        "docker exec --privileged web sh",
        "docker container create --privileged --name c alpine",
        "podman run --privileged=1 alpine sh",
        "nerdctl run \"--privileged\" alpine sh",
        "ctr run --privileged docker.io/library/alpine:latest c1 sh",
        "F=--privileged; docker run $F alpine sh",
        "docker run \\\n  --rm \\\n  --privileged \\\n  alpine sh",
        "docker run --rm --pid=host --privileged alpine nsenter -t 1 -m -u -n -i sh",
        "docker run --rm --privi''leged alpine sh",
        "docker run --rm --pid=host alpine ps",
        "docker run --rm --pid host alpine ps",
        "docker run --rm --pid=\"host\" alpine ps",
        "podman run \"--pid\" \"host\" alpine ps",
        "podman run --pid=ns:/proc/1/ns/pid alpine ps",
        "docker run --rm -v /:/host alpine sh",
        "docker run -e A='x;y' -v /:/host alpine sh",
        "docker run \"-v\" \"/:/host\" alpine sh",
        "docker run -v /:/h alpine sh",
        "docker run -v '/':/h alpine sh",
        "docker run --volume /:/host alpine sh",
        "docker run --volume=/:/host:ro alpine sh",
        "docker run -v=/:/host alpine sh",
        "docker run -v/:/host alpine sh",
        "docker run -itv /:/host alpine sh",
        "docker run -v /.:/host alpine sh",
        "docker run -v //:/host alpine sh",
        "docker run -v /../:/host alpine sh",
        "docker run -v /proc/1/root:/host alpine sh",
        "podman run -v /:/host alpine sh",
        "docker run --mount type=bind,source=/,target=/host alpine sh",
        "docker run --mount=type=bind,target=/host,src=/ alpine sh",
        "docker run --mount \"type=bind,source=/,target=/host\" alpine sh",
        "docker service create --mount type=bind,source=/,target=/host alpine sleep 1d",
        "ctr run --mount type=bind,src=/,dst=/host,options=rbind:rw docker.io/library/alpine:latest c1 sh",
        "nsenter -t 1 -m -u -n -i sh",
        "nsenter -t1 -a sh",
        "nsenter -at 01 sh",
        "nsenter -m -u -t \"1\" sh",
        "nsenter --target 1 --mount --uts sh",
        "nsenter --target=1 --mount sh",
        "nsenter --wd='/tmp/a;b' -t 1 -m sh",
        "nsenter \\\n  -t 1 -m sh",
        "nsenter --mount=/proc/1/ns/mnt sh",
        "docker run --rm alpine nsenter -t 1 -m sh",
        "curl --unix-socket /var/run/docker.sock http://localhost/containers/json",
        "curl -s --unix-socket /var/run/docker.sock -X POST -H \"Content-Type: application/json\" -d @body.json http://localhost/containers/create",
        "S=/run/podman/podman.sock; curl --unix-socket \"$S\" http://d/v4.0.0/libpod/info",
        "curl --unix /var/run/docker.sock http://localhost/info",
        "curl --abstract-unix-socket docker.sock http://localhost/info",
        "curl --unix-socket ~/.docker/run/docker.sock http://localhost/version",
        "nc -q1 -U /var/run/docker.sock",
        "ncat -U /run/containerd/containerd.sock",
        "socat - UNIX-CLIENT:/var/run/crio/crio.sock",
        "curl http://127.0.0.1:2375/containers/json",
        "curl -s 127.0.0.1:2375/version",
        "wget -qO- http://[::1]:2376/info",
        "python3 -c \"import urllib.request as u; print(u.urlopen('http://localhost:2375/info').read())\"",
        "nc 127.0.0.1 2375",
    ] {
        let analysis = analyze_command(cmd, None);
        assert_eq!(analysis.recommendation, "deny", "{cmd}");
        assert!(blocks_for_agent(&analysis), "{cmd}");
        assert!(
            analysis
                .signals
                .iter()
                .any(|s| s.signal == "container_escape" && s.score == 60),
            "refused, but not as a container escape: {cmd}: {:?}",
            analysis.signals
        );
    }
}

/// The property that makes the rule worth leaving on: none of this is refused,
/// or even flagged.
#[test]
fn ordinary_container_work_is_allowed() {
    for cmd in [
        "docker ps",
        "docker run --rm alpine echo hi",
        "docker run --rm -v \"$PWD\":/src alpine sh -c 'ls /src'",
        "docker run --rm -v /srv/data:/data:ro alpine ls /data",
        "docker run --rm -v .:/app -w /app node:22 npm test",
        "docker run --rm -v ./:/app -w /app node:22 npm test",
        "docker run --rm -v ~/.cache:/cache alpine ls /cache",
        "docker run --rm --privileged=false alpine sh",
        "docker run --rm --privileged=0 alpine sh",
        "docker run --rm --pid=container:web alpine ps",
        "docker run --rm --pids-limit 100 alpine sh",
        "docker run --rm --mount type=bind,source=/srv/data,target=/data alpine ls /data",
        "docker run --rm --mount type=volume,source=cache,target=/cache alpine ls /cache",
        "docker run -d -p 2375:8080 app:dev",
        "docker exec -it web sh",
        "docker build -t app:dev .",
        "docker compose up -d",
        "docker inspect -f '{{.HostConfig.Privileged}}' web",
        "podman run --rm alpine echo hi",
        "nsenter -t 12 -n ip a",
        "nsenter -n -t 100 ss -ltn",
        "nsenter -t \"$(docker inspect -f '{{.State.Pid}}' web)\" -n ss -ltn",
        "readlink /proc/1/ns/net",
        "ls -l /var/run/docker.sock",
        "export DOCKER_HOST=unix:///var/run/docker.sock",
        "DOCKER_HOST=tcp://127.0.0.1:2375 docker ps",
        "curl --unix-socket /tmp/app.sock http://localhost/health",
        "curl http://localhost:8080/health",
        "curl http://localhost:23750/health",
        "diff --unified a.txt docker.sock.md",
        "grep -rn -- --privileged docs/",
        "ls -la",
        "git status",
        "cargo build --release",
    ] {
        let analysis = analyze_command(cmd, None);
        assert_eq!(
            analysis.recommendation, "allow",
            "ordinary work: {cmd}: {:?}",
            analysis.signals
        );
    }
}
