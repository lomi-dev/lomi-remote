if [ -f "$HOME/.bashrc" ]; then
  source "$HOME/.bashrc"
fi

__lomi_file_uri_path() {
  local LC_ALL=C
  local input=$1 encoded='' character byte
  local index
  for ((index = 0; index < ${#input}; index++)); do
    character=${input:index:1}
    case "$character" in
      [a-zA-Z0-9._~/-]) encoded+=$character ;;
      *)
        printf -v byte '%%%02X' "'$character"
        encoded+=$byte
        ;;
    esac
  done
  printf '%s' "$encoded"
}

__lomi_prompt() {
  local status=$?
  __lomi_ready=0
  local directory
  directory=$(__lomi_file_uri_path "$PWD")
  printf '\033]133;D;%s\007\033]7;file://localhost%s\007\033]133;A\007' "$status" "$directory"
  return "$status"
}

__lomi_prompt_end() {
  local status=$?
  __lomi_ready=1
  return "$status"
}

__lomi_preexec() {
  if [[ ${__lomi_ready-0} == 1 && $1 != __lomi_prompt ]]; then
    __lomi_ready=0
    printf '\033]133;C\007'
  fi
  return 0
}

__lomi_prompt_commands=(__lomi_prompt "${PROMPT_COMMAND[@]}" __lomi_prompt_end)
printf -v PROMPT_COMMAND '%s\n' "${__lomi_prompt_commands[@]}"
unset __lomi_prompt_commands

if (( BASH_VERSINFO[0] > 4 || (BASH_VERSINFO[0] == 4 && BASH_VERSINFO[1] >= 4) )); then
  PS1="$PS1"'\[\e]133;B\a\]'
  PS0=$'\e]133;C\a'"${PS0-}"
elif [[ -z $(trap -p DEBUG) && $- != *T* ]] && ! shopt -q extdebug; then
  __lomi_ready=0
  trap '__lomi_preexec "$BASH_COMMAND"' DEBUG
  PS1="$PS1"'\[\e]133;B\a\]'
fi
