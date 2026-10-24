# Agent identity and trust

An agent names itself: the `--agent` flag its hook was wired with, its
environment and its session id are all its own to choose. So the guard keeps
two separate questions apart: how far that name is backed (trust), and what
you decided about that kind of agent (`innerwarden agents approve`, `profile`,
`allow`, `revoke`).

Trust has three levels, and in Community the highest one is never reached:

- `declared`: only the agent's own word says what it is. Every agent started
  without `contain --identity` is here.
- `observed`: the agent runs in a jail started by `innerwarden contain
  --identity`, and its hook, reading from inside the jail, found what the
  launcher recorded (the same process and mount namespaces, a record it
  cannot rewrite). This is the most a reading from inside the jail can give.
  Everything it compares is something the agent's own process could set up
  for itself, so it never proves the jail. A launcher installed in your home
  folder, or a jail with no scope of its own, is `observed` too, and the
  dashboard says why.
- `host_verified` (shown as confined): the instance runs in a boundary it
  cannot leave, confirmed by a witness outside the agent. Community has no such
  witness; it exists only where InnerWarden Active Defence is installed on the
  same host and confirms the instance from outside the jail. The Community
  dashboard never shows an instance as confined, whatever a label in a graph
  or a record says.

A rule in an agent profile or an instance exception that RELAXES your general
rules applies only to a confined instance. With Community alone, such a
relaxation is recorded in `agent-profiles.toml` and is not applied: your
general rules keep deciding, and a decision says when a profile would have
allowed it. A rule that TIGHTENS (refuses more) applies at every trust level.

The hook in a jail never applies a relaxation on its own word. When your
general rules send a shell command of an identified instance to review, the
hook asks InnerWarden Active Defence on the same host, if it runs there, and
the host decides. The hook keeps the stricter of its own decision and the
host's, so a deny and your own profiles file still win, and the trust it
records stays its own reading from inside the jail. A review the hook would
block on its line is still asked about, because the host may relax it; the
host lets nothing of it run that the hook does not keep. When the host
refuses a command on its own (it will not start a program in it), the hook
says: "Active Defence on this host will not start a program in this command."
and records the block as the host's.

A profile in the system file (`/etc/innerwarden/agent-profiles.toml`,
`schema_version = 2`) can ask for more: with `ask_host = "every_command"`
the hook asks the host about every shell command of that type's identified
instances, confined or not, that it does not refuse itself, including the
ones your general rules allow. A command they allow, your suppressions
included, is made stricter only by a refusal of the host's own: the host's
reading of your general rules does not override your suppressions. A command
the hook refuses is never asked about. It costs a request to the host on
every command, bounded like the others.

A command the hook refuses itself, where it would ask the host about a
review (an identified instance, the profiles in force, Active Defence on the
host), is reported to the host once the refusal stands, so the host's case
of that session lists it with the commands it was asked about. The report
is the hook's refusal, sent after it decided: nothing the host answers
changes it, and an Active Defence that does not know the report refuses it,
with nothing else changing. Monitor refuses nothing, so it reports nothing. Only the system file says
`ask_host`; the user's file never does, and a file of schema 1 that says it
is refused. Every program that reads the system file must read schema 2
before you write one: an older `innerwarden` refuses a file of schema 2, and
so does an older Active Defence on the host, which reads the same file.
Update both first.

A profile of schema 2, in either file, can also say when its jail starts and
what of the home it hides, under `[profile.<type>.jail]`:

- `start = "only_when_admitted"`: `contain --identity` starts the agent only
  once Active Defence on the host has admitted the jail. Otherwise it says
  "Active Defence on this host did not admit this jail, and its profile
  starts it only when admitted.", says what to check and which file asks for
  it, and exits 2 with nothing started. Inside the jail the command starts
  through `innerwarden contain-gate`, which will not start it without the
  record of that admission, so a launcher stopped while it waits (a Ctrl-C,
  killed) starts nothing either. On macOS such a profile never starts.
- `hide_home = [".cache/git/credential"]`: home paths the jail covers with an
  empty mount on Linux, or denies on macOS. A link on the way is followed and
  the place it leads to is hidden. A path that leads outside the home, or
  that would cover the project, the guard or the agent's own settings, stops
  the launch; a profile's read-only path under it is left out (the hidden
  path wins, so nothing of it is shown or written), said, and the jail
  starts. A home folder the jail writes that is itself a link (`~/.cache` on
  another disk) counts as the home where it leads. On Linux a path whose
  way goes through a link in a folder the jail
  writes (`~/.cache/git` a link, or a dotfiles manager's `~/.config/gh`
  link) stops the launch: a program in the jail could replace that link with
  a folder of its own, which your programs would then read and write at that
  name, so replace the link with the folder it leads to. On macOS the jail
  starts, and keeps each such link in place instead, also one further down
  a chain (`~/.local/a`, where `~/.cache/git` leads to `~/.local/a/git` and
  `~/.local/a` is a link too): no program in the jail can remove, rename or
  replace it. On Linux a path
  that is not there yet, in a folder the jail writes,
  is made empty (mode 0700) first, so what a program makes there later stays
  hidden too. Each folder the jail writes between such a path and your home
  is pinned as below, so no program in the jail renames it away from the
  path's cover.

The user's file can only tighten these: the stricter `start` and every hidden
path of both files hold. When Active Defence sends a note about the jail (for
example, whether kernel protection is in effect for the session), it prints
it as `innerwarden contain: <note>`.

Every Linux jail keeps the host's name resolution working: where
`/etc/resolv.conf` is a link into `/run`, the file it leads to is shown
read-only in the jail, and nothing else of the host's `/run`. Where that file
sits in a folder of resolver data alone (resolvconf), the folder is shown, so
the jail follows the host when the network changes. Elsewhere
(systemd-resolved, NetworkManager) a jail keeps the resolver file it started
with until the agent is restarted.

On macOS every jail keeps in place the folders above what it hides: the
project, `~/.config` (which holds InnerWarden's own folder) and each folder
between the project and a `--deny-read` path cannot be renamed, removed or
replaced by a link from inside the jail, so nothing it hides is shown at
another name. So is every other folder the jail may write above a place it
hides: `~/.cache` or `/tmp` above a project there that holds a `--deny-read`
path, or a folder above where a hidden dotdir or a profile's hidden home path
leads, or above a profile's read-only path. The jail still
writes in them, finds them writable and sets their mode and times (`rsync -a`
or `cp -a` into the project works); only renaming, removing or replacing the
folder itself is refused. Where such a folder is not there yet (`~/.config`
on an account that has none), `innerwarden contain` makes it first, empty and
0700, and says so; a dry run makes nothing and names each folder a real run
would make.

A profile's read-only path (`extra_ro`) is read-only in every jail, wherever
it is, and wherever a link on its way leads (below). On Linux one inside a
folder the jail may write (the project, `~/.local`) is kept read-only only
where bubblewrap binds a folder from a descriptor (below): bubblewrap 0.10.0
or later, or a package whose security update added `--ro-bind-fd` (the
current packages of Debian 12, Ubuntu 22.04 and 24.04, and RHEL 9 have it).
On macOS the sandbox
denies writing it also inside a folder the jail may write (the project,
`~/.cache`, `~/.local`, `~/.config`, `/tmp`, `~/.claude.json`); before, the
macOS jail never denied it, so a program in the jail wrote it. A tool that
has to write at such a path (Claude Code updating itself in
`~/.local/share/claude/versions`) gets "Operation not permitted" there:
update it outside the jail, or leave that path out of `extra_ro`.

Where a profile's read-only path is a link, or goes through one, the jail
keeps it read-only where it leads, and shows nothing it would not show
otherwise. On macOS, where the sandbox lets the jail read everywhere, the path
is denied writing as named and where it leads, and each link on the way that
sits in a folder the jail may write is kept in place. On Linux the path is
laid read-only at each place the jail shows the folder it leads to: with
`~/.local` kept as your link to another disk, at `~/.local/...`, where the
agent runs it. Your own links, in folders no jail writes (`~/code` a link to
another disk), are followed as before. A link in a folder a jail writes (a
program in an earlier jail can make one in `~/.local`) is followed only to a
place the jail shows already, and the start says on one line that the link
itself is not held ("... is a link in a folder a program in the jail can
write: the jail keeps <where it leads>, where it leads, read-only, but that
program could replace the link; ..."): replace the link with the folder it
leads to. Such a link to a place the jail shows nothing else of is not
followed: the path is left out of the jail, and the start says so ("... the
jail does not follow it, and starts without the extra path; list the real
folder instead"). Before, the launcher followed every link: a program in an
earlier jail that replaced the path, or a folder on the way to it, with a link
made the next Linux jail show where the link led, a folder of your home the
jail hides or the host's `/tmp` and the sockets in it, and a link into
`~/.ssh` kept the agent from starting. The real Linux run binds each read-only
path, and each folder it pins above one, from a descriptor it opens just
before bwrap starts, one folder at a time with no link a program in a jail can
change followed: a link put there after the launcher looked is never what
bwrap binds, and a place that changed so stops the launch, said. A bwrap that
cannot bind from a descriptor (its `--help` lists no `--ro-bind-fd`: upstream
before 0.10.0, or a distribution's package without that security update)
cannot hold in place a path in a folder a jail writes, so such a path is left
out and said ("... does not make it read-only; bubblewrap 0.10.0 or later,
... keeps it"): the jail shows it, and its programs can write it, where
before this release the jail laid it read-only by name. A profile with
`start = "only_when_admitted"` asked for every defence in effect, so there
it does not start: the launch stops with a line that names each such path
and what to do (update bubblewrap, or take the path out of `extra_ro`). A
read-only path in a place the jail hides is left out, said, and the jail
starts (on Linux `~/.ssh`, `~/.gnupg`, `~/.aws`, `~/.mozilla`,
`~/.thunderbird` and InnerWarden's own folder; on macOS `~/.ssh`, `~/.gnupg`,
`~/.aws`, InnerWarden's own folder, `~/Library/Mail`, `~/Library/Messages` and
`~/Library/Safari`; and where one of them leads), as is one under a profile's
`hide_home` path, your home or a folder above it, and with `--identity` `/run`
and `/sys`: before, such a path stopped the launch. One that holds such a
place where the jail shows it already (`~/.config`, which holds InnerWarden's
own folder) is laid read-only, and the place stays hidden; on Linux one that
holds such a place where the jail shows nothing else of it is left out. A
read-only path never keeps a hidden dotdir from being hidden where a link
leads it: that place is hidden, and the read-only path in it left out. A path
that is not there is left out without a word, as before.

A linked git worktree's folders are shown, read-write, only where git made
them for this project: the worktree's git folder sits in the `worktrees`
folder of its repository and names the project's `.git` file back, or (a
submodule) its config names the project as its work tree; the repository is a
git folder (`HEAD`, `objects`, `refs`); both belong to you; no link is on the
way to either (git writes these paths with none); and neither is your home, a
folder above it, a place the jail hides, or in a hidden folder of your home
that the jail does not show on Linux and lets no program write on macOS
(`~/.kube`, `~/.docker`, `~/.password-store`, `~/.dotfiles`). Every folder on
the way is there, as the kernel takes the path: one named through a folder
that is not there and back (`nx/../L`) is none. A hidden folder of your home
that every jail shows writable (`~/.config`, `~/.local`, `~/.cache`) is fine:
a worktree of a repository kept there (an editor's configuration in
`~/.config/nvim`) works as before. The jail shows such a repository through
that folder, as it shows one in the project, so it binds nothing more for it
(unless a profile's read-only path holds it: the worktree's write wins there,
as before), and says nothing of a `.git` file that names a folder there.
A program in the jail writes the project, so before, a `.git` file it wrote
(`gitdir: ~/.kube`, `~/bin`, another repository, on macOS
`~/Library/LaunchAgents`) had the next jail, with or without `--identity`,
show that place writable. Such a file is left alone now, the start says why
on one line, and the jail starts; git in a Linux jail then sees no repository
there, and git in a macOS jail cannot commit there (it may still read it). A
worktree whose folder lies over the place InnerWarden's own folder, a hidden
dotdir or a link inside one leads to is left out the same way, where the
launch stopped before.
A worktree moved by hand needs `git worktree repair`. Where bwrap binds a place
from a descriptor (bubblewrap 0.10.0 or later, or a package with the security
update that added it), the real Linux run binds a worktree's folders from
descriptors it opens just before bwrap starts, as it binds a profile's
read-only paths, so a folder on the way swapped for a link after the launcher
looked stops the launch. An older bwrap binds them by name, as 1.5.5 did, and
the start says nothing of it: a program in a jail of a project that holds the
repository (its main worktree, or a folder above it) could swap a folder on
the way for a link while this jail starts. A repository made with
`--separate-git-dir` (`git init` or `git clone`, the layout of dotfile
managers such as yadm and vcsh) keeps nothing that names the project back,
so it cannot be told apart from such a file: it is not shown either, where
before git in the jail worked there (one in a folder the jail shows anyway,
such as `~/.local/share`, still works). Move its git folder
into the project in place of the `.git` file, or work in a linked worktree
(`git worktree add`); the start line says so. The
launcher reads the project's git files without waiting and only as small
regular files, so a FIFO put there never holds it.

Where a place the jail hides is a link, the jail hides the place it leads
to: `~/.ssh`, `~/.gnupg` or `~/.aws` kept as a link into a folder the jail
shows (`~/.ssh` a link to `.config/ssh`), a link inside one of them
(`~/.ssh/config` a link into `~/.config/dotfiles`, as GNU stow and chezmoi
make one per file), a `--deny-read` path of the project, or InnerWarden's own
folder. Every link on the way is followed. On Linux that place is covered
wherever a folder the jail shows holds it, and each folder the jail writes
between the cover and your home is a mount point of its own, so a program in
the jail can neither read the place nor rename it away from the name your
link uses; a dotdir's place that is not there yet is made first, empty and
0700, so nothing the agent writes there reaches it (a `--deny-read` path that
is not there is not hidden). On macOS it is denied, read and write, also
outside your home, and each folder above it that the jail may write, the
project included, is closed to renaming and removal (the jail still writes in
it). The launcher looks for the links inside those dotdirs as far as 100000
entries and 32 folders deep, and says where it stops short. A link never
moves a mask or a deny onto what the jail needs: the guard, the agent's
settings or a file in them, the project, the system's folders, and for a
`--deny-read` path a read-only path of the profile (a hidden dotdir or
InnerWarden's own folder is hidden where it leads even there). Nor does a `--deny-read` link in the project, which the agent can
change, move one onto what the jail runs on: on Linux a place outside your
home, on macOS a place of the system outside the project. Each such place is
left as it is, and `innerwarden contain` says so, with what to do (on Linux
only where the jail shows that place: elsewhere it is not in the jail at
all). A dotdir that leads into the project is hidden there, and said. A link
stops the launch only here: a hidden dotdir, a link inside one, InnerWarden's
own folder or, in an identified Linux jail, the launcher's records folder or
a profile's hidden home path (above), whose way goes through a link in a folder the jail writes (`~/.aws` a link to
`~/.cache/aws-link`, itself a link) is refused, since no mount or deny pins a
link and a program in the jail could replace it on the host (replace that
link with what it leads to); on Linux, InnerWarden's own folder kept as a
link is refused for the same reason (replace it with the folder it leads
to), and so is a link inside a hidden dotdir that leads to nothing yet where
the jail shows that place (make it, or remove the link); and a project path
over the place InnerWarden's folder leads to is refused (a worktree's folder
there, or over the place a hidden dotdir leads to, is left out, above). A
profile's
`hide_home` path keeps its own rule, above: one that leads outside the home
stops the launch.

An identified Linux jail keeps Claude Code's own state in the `~/.claude` it
already shares with you. The jail's home is an empty folder of its own, so
Claude Code's settings file, `~/.claude.json`, used to be gone at every launch
(and Claude Code said, from the second launch on, that it was missing). In the
jail it now leads to `~/.claude/.claude.json`, so what Claude Code saves there,
an MCP server you add or its first-run answers, is still there at the next
launch. Your own `~/.claude.json` is not shown in the jail, and the jail's
Claude Code never uses it. Nor are the copies Claude Code keeps of it in
`~/.claude/backups`: each identified jail has an empty `~/.claude/backups` of
its own, and the copies made there are gone when the jail ends. The first
identified launch starts Claude Code with a new file of the jail's own, so it
may ask its first-run questions once. (Where your own `~/.claude.json` is a
link, or a hard link, to a file in `~/.claude`, that file is shared with the
jail like the rest of the folder, and the jail makes no link to it. Where you
point Claude Code at `~/.claude` with `CLAUDE_CONFIG_DIR`,
`~/.claude/.claude.json` is the file it uses, in the jail and out of it.)
Claude Code is process 2 in every jail and lists each running session by its
process id, so each identified jail also has an empty `~/.claude/sessions` of
its own: two jails at once do not write the same session file, and none sees
the sessions running outside it. Both folders are covered at every place the
jail shows them, a `~/.claude` that is a link into `~/.config` and a project
that is `~/.claude` included. All of this is for Claude Code's own folder at
`~/.claude`, where it is unless `CLAUDE_CONFIG_DIR` names another: the jail
leaves another folder as it is, and jails at once share the session list in
it.

Claude Code keeps its file in the jail's own home, as before, where a hidden
home path covers `~/.claude/.claude.json`, where a read-only path of the
profile shows it, `~/.claude` or `~/.claude.json`, where that place is a link
or anything other than a file, or where your own `~/.claude.json` is that file
or leads into `~/.claude` or to nothing. Where one of the two folders cannot be the jail's
own (a link is there, the project is inside it, or it could not be made), the
jail shows the host's, and `innerwarden contain` says so. Limit: two jails at
once share the one settings file, and Claude Code's lock on it is each jail's
own, so a change one jail saves at the same moment as another can be lost (a
save is never left half written). Every jail, with `--identity` or without,
shares `~/.claude` with you, so what a program in any jail writes to
`~/.claude/.claude.json` is what the next identified Claude Code loads, as
with `~/.claude/settings.json`: an MCP server listed there starts with it,
outside `innerwarden proxy` unless the entry runs through it, and a project
marked trusted there skips Claude Code's trust question. A jail started
without `--identity` is
unchanged: Claude Code's settings file is still gone at every launch there,
and two such jails at once still share `~/.claude/sessions` and see the
host's. On macOS the jail lets Claude Code use your own `~/.claude.json`, as
before.

Where a per-agent relaxation applies:

- Linux;
- the `innerwarden` that starts the jail is installed system-wide and owned by
  root (for example `/usr/local/bin/innerwarden`), not in your home folder;
- the agent was started with `innerwarden contain --identity`;
- InnerWarden Active Defence runs on the same host with agent identity turned
  on and an active licence, and it placed the jail in a scope of its own;
- Active Defence can tell which jail the asking process belongs to;
- shell commands your general rules sent to review (never MCP tools or file
  edits);
- the `innerwarden` inside the jail is a version that asks the host.

Anywhere else the relaxation is recorded and not applied. Applies to shell
commands only; MCP tools and file edits keep your general rules. A profile
applies to any program started in a jail under its agent's name: the type is
the name given at launch.

An identified jail starts its programs under a seccomp filter, in the style of
Flatpak: no new user namespaces, no joining other namespaces, no new btrfs or
bcachefs subvolumes or snapshots, and no `TIOCSTI` or `TIOCLINUX`, the
terminal commands that push input into your terminal. Its
programs run with no capability, also when `contain` itself runs as root.
Programs that need their own user namespace (Chromium's sandbox, rootless
containers, an agent's own bubblewrap sandbox) do not work inside it; turn the
agent's own sandbox off inside `innerwarden contain`. A 32-bit program (i386
or x32 on x86_64, arm on aarch64) is ended at its first call in an identified
jail. A jail started without `--identity` gets only the terminal rule and the
subvolume rule, and applies them to 32-bit programs too, which run in it as
before. Every jail refuses new subvolumes and snapshots because a snapshot of
the project would show the files the jail hides in it (`.env`, `secrets/`,
each `--deny-read` path).

Where the host cannot start a jail with the filter (a kernel without seccomp
filters, a binary run under another architecture's emulation, a build for an
architecture other than x86_64 or aarch64), the jail runs without it and
`contain` says so when it starts, naming the keystrokes and the snapshots its
programs can then make. An identified jail whose host takes only the plain
jail's filter gets that one, and `contain` says user namespaces stay open,
joining other namespaces too, and that a 32-bit program runs in it; the
terminal rule and the subvolume rule still hold.

Limits: the filter covers those commands only. It refuses only new
subvolumes and snapshots: a snapshot made before the jail started, in a folder
the jail shows, still holds the files the jail hides (`.env`, `secrets/`, each
`--deny-read` path), and a program in the jail can read them there. Keep such
snapshots out of the project and out of the folders the jail shows. The jail
shares the host's network, so a program in it can still reach any abstract unix socket,
a desktop's X server among them, and through X type into another window. On
a kernel older than 4.8, a program in the jail that traces another can change
a call after the filter has seen it: there an identified jail does not close
user namespaces, and `contain` says the filter is weaker. This is not
yet proven on RHEL 9 or Rocky 9.

A tool that reads the command line of a running jail's bubblewrap (from
`/proc`) finds an identified jail's filter first: that command line starts
with `--seccomp <fd>`. Where bwrap binds a place from a descriptor, the real
run of any jail binds the folders it pins, a profile's read-only paths and a
worktree's git folders with `--bind-fd` and `--ro-bind-fd` (each followed by
the descriptor and the place), not `--bind` and `--ro-bind-try`.

