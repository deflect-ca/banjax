#!/usr/bin/env bash
# Copyright (c) 2026, eQualit.ie inc.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.

# PostToolUse hook for Edit|Write: when an edited .go file is not gofmt-clean,
# tell the model so it fixes it now rather than at commit time. Silent otherwise.

command -v jq >/dev/null 2>&1 || exit 0
command -v gofmt >/dev/null 2>&1 || exit 0

file="$(jq -r '.tool_input.file_path // empty')"
case "$file" in *.go) ;; *) exit 0 ;; esac
[ -f "$file" ] || exit 0
[ -n "$(gofmt -l "$file" 2>/dev/null)" ] || exit 0

msg="$file is not gofmt-clean. Run: gofmt -w $file"
case "$file" in
*/internal/integrity_check.go | */internal/integrity_check_test.go | */internal/kafka.go)
    msg="$msg (this file already had gofmt drift before your change; formatting it touches unrelated lines, so put that in its own commit, separate from your change)"
    ;;
esac

jq -cn --arg m "$msg" '{hookSpecificOutput: {hookEventName: "PostToolUse", additionalContext: $m}}'
exit 0
