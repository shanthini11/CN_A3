# CN_A3 Team Plan (3 members)

## Shared rule
Keep the data format returned by `parser.parse_packet()` unchanged unless the whole team agrees on a change. `main.py` connects the modules.

## Member 1 - Capture and integration
- Own `capture.py` and `main.py`.
- Confirm Scapy can capture raw frames on the chosen interface.
- Handle interface input, packet-count/time input, errors and the main menu.
- Do not decode IP/TCP/UDP headers in Scapy.

## Member 2 - Header parsing
- Own `parser.py` and `test_parser.py`.
- Parse IPv4, TCP and UDP directly from bytes.
- Explain byte offsets, big-endian integers, IP header length, TCP flags, and payload lengths.
- Run `python test_parser.py` after changes.

## Member 3 - Display and filters
- Own `display.py` and `filters.py`.
- Keep the summary fields required by the assignment.
- Test protocol, source/destination IP, and source/destination port filters.
- Check the detailed view includes header fields and payload hex/text.

## GitHub workflow
1. Each member clones the repository.
2. Each member creates their own branch and edits their assigned files.
3. Commit and push that branch.
4. Open a Pull Request into `main`.
5. Another member reviews it, then the owner merges it.
6. Before starting new work, run `git pull origin main` and merge/rebase as the team has agreed.

Suggested branch names: `capture-feature`, `parser-feature`, `display-filter-feature`.
