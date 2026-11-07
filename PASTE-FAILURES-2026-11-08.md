# Paste Channel Failures - 2026-11-08

Corrupted characters: dollar sign, double underscore, backtick, double asterisk. These are stripped or converted before PowerShell sees them.

Damage this session: 2 nested git clones created then deleted. Global pip editable install re-pointed twice, fixed. 4 no-op edit attempts on README and WORKFLOW. 1 here string wrote angle bracket prefixes on every line, restored from backup.

Working pattern: single line commands only. Build strings from char codes when they contain corrupted characters: [string]::new([char[]](72,105)) yields Hi. Verify every write with Get-Content or Select-String in the same command. Prefer VS Code for prose and hyphen heavy text.

Session start test: run Get-Date and Write-Output abc. A timestamp plus exactly abc means the channel is safe for plain text and single line commands.

Resolution: every destructive incident this session traced to a multi line paste. Do not paste multi line text into PowerShell. Markdown from assistant messages is not a command.

Do not delete this file until the channel is confirmed fixed at source.
