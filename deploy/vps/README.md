# VPS service workspace

Run the pinned `install.sh` recipe. After setup, it invokes `render_service.py`
as the service account to create and check the selected workspace. It then
renders the unit separately using isolated system Python as root; output from
the service account is never installed as the unit. Only then does it publish
and enable the systemd unit. The service account controls its configuration and
probe process, so the probe is a usability check rather than proof that the
later rendered workspace was checked. Privileged rendering requires the service
home's ancestors to be root-owned directories without group or world write
access. `WorkingDirectory` and `ReadWritePaths` use the
saved absolute workspace for local and container sandboxes; spaces and systemd
percent specifiers are escaped. With an SSH sandbox, the service instead uses
the local `.maverick/service-workspace` directory. The configured SSH workspace
remains a remote POSIX path and is neither expanded nor created on the VPS.
Setup requires an SSH destination (`user@host` or an SSH config alias), but
does not connect to it. Connectivity is checked when the SSH sandbox starts.

Do not copy `maverick.service` directly: it contains renderer placeholders.
If you change the saved workspace later, regenerate the unit through the
installer before restarting the service. A missing `.env` is allowed for a
setup completed without provider keys; configure a provider before running
provider-backed work.

Native Linux acceptance still requires checking `systemctl status maverick`
after start and confirming a harmless local workspace operation. Offline
renderer tests cannot establish systemd, filesystem ownership or mount policy
on a deployed VPS.
