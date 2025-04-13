#!/bin/bash

VERSION="V0.7.1"
MAX_LOG_SIZE=524288
IPTABLES_PATH="/usr/sbin/iptables"
IP6TABLES_PATH="/usr/sbin/ip6tables"
CONFIG_FILE="/etc/rent/config"
CP_FILE="/etc/rent/config.original"
LOG_FILE="/var/log/rent.log"
TRAFFIC_SAVE_FILE="/var/log/rent_usage.dat"
IPTABLES_SAVE_FILE="/etc/iptables/rent_rules.v4"
IP6TABLES_SAVE_FILE="/etc/iptables/rent_rules.v6"
HTML_FILE="/var/www/index.html"
WEB_PORT_FILE="/etc/rent/port.conf"
WEB_PID_FILE="/var/run/rent_web.pid"
WEB_LOG="/tmp/web_service.log"
PASSWORD_FILE="/etc/rent/web_pass"

mkdir -p /etc/rent /etc/iptables /var/www

touch "$TRAFFIC_SAVE_FILE" "$IPTABLES_SAVE_FILE" "$IP6TABLES_SAVE_FILE" "$LOG_FILE" "$WEB_PORT_FILE" "$HTML_FILE"

if [ ! -f "$CONFIG_FILE" ]; then
    cat > "$CONFIG_FILE" << EOF
# 配置格式：单端口/端口范围/两者的自由组合 月度流量限制(GiB) 重置日期(1-28日)
# 例如：
# 6020-6030 100.00 1 # 6020-6030端口 月流量限制100G 每月1号重置流量
# 443,80 1.5 15
# 5201,5202-5205 1 20 
# 7020-7030,7090-7095,7096-8000 10 12
EOF
fi

clear_log() {
    if [ -f "$LOG_FILE" ] && [ "$(stat -c %s "$LOG_FILE")" -gt "$MAX_LOG_SIZE" ]; then
        > "$LOG_FILE"
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] 日志文件已自动清空" >> "$LOG_FILE"
    fi

    if [ -f "$WEB_LOG" ] && [ "$(stat -c %s "$WEB_LOG")" -gt "$MAX_LOG_SIZE" ]; then
        > "$WEB_LOG"
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] Web服务日志已自动清空" >> "$WEB_LOG"
    fi
}

log() {
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] $1" >> "$LOG_FILE"
    echo "$1"
}

parse_port_range() {
    local range=$1
    local parsed_ports=()

    IFS=',' read -ra parts <<< "$range"
    for part in "${parts[@]}"; do
        IFS=- read -r start_port end_port <<< "$part"
        end_port=${end_port:-$start_port}

        if [[ "$start_port" =~ ^[0-9]+$ && "$end_port" =~ ^[0-9]+$ ]] && (( start_port <= end_port )); then
            if [[ "$start_port" == "$end_port" ]]; then
                parsed_ports+=("$start_port")
            else
                parsed_ports+=("$start_port:$end_port")
            fi
        else
            log "错误，端口格式无效: $part"
            exit 1
        fi
    done

    echo "${parsed_ports[*]}" | tr ' ' ','
}

handle_port_rules() {
    local action="${1}"
    local port_range="${2}"
    local targets="${3:-DROP}"

    local port_spec
    port_spec=$(parse_port_range "${port_range}") || {
        log "PORT_ERROR: ${port_range}" >&2
        return 1
    }

    process_rule() {
        local chain="$1"
        local ports_flag="$2"

        for ipt_cmd in "$IPTABLES_PATH" "$IP6TABLES_PATH"; do
            for proto in tcp udp; do
                for target in "${target_list[@]}"; do
                    if "$ipt_cmd" -C "$chain" -p "$proto" --match multiport "$ports_flag" "$port_spec" -j "$target" 2>/dev/null; then
                        if [[ "$action" = "-D" ]]; then
                            "$ipt_cmd" -D "$chain" -p "$proto" --match multiport "$ports_flag" "$port_spec" -j "$target"
                        fi
                    else
                        if [[ "$action" = "-A" || "$action" = "-I" ]]; then
                            "$ipt_cmd" "$action" "$chain" -p "$proto" --match multiport "$ports_flag" "$port_spec" -j "$target"
                        fi
                    fi
                done
            done
        done
    }

    IFS=',' read -ra target_list <<< "${targets}"

    process_rule "PORT_IN" "--dports"
    process_rule "PORT_OUT" "--sports"
}

initialize_iptables() {
    log "初始化端口流量限制服务"

    for ipt_cmd in "$IPTABLES_PATH" "$IP6TABLES_PATH"; do
        for chain in PORT_IN PORT_OUT; do
            if "$ipt_cmd" -L "$chain" &>/dev/null; then
                "$ipt_cmd" -F "$chain"
            else
                "$ipt_cmd" -N "$chain"
            fi
        done

        if ! "$ipt_cmd" -C INPUT -j PORT_IN &>/dev/null; then
            "$ipt_cmd" -I INPUT 1 -j PORT_IN
        fi
        if ! "$ipt_cmd" -C OUTPUT -j PORT_OUT &>/dev/null; then
            "$ipt_cmd" -I OUTPUT 1 -j PORT_OUT
        fi
    done

    while IFS=$' \t' read -r port_range traffic_limit date _extra || [[ -n "$port_range" ]]; do
        port_range=${port_range%$'\r'}
        traffic_limit=${traffic_limit%$'\r'}
        date=${date%$'\r'}
        
        [[ "$port_range" =~ ^[[:space:]]*# || -z "$port_range" ]] && continue
        
        if [[ -z "$traffic_limit" || -z "$date" || -n "$_extra" ]]; then
            log "错误：行格式不正确 - $port_range $traffic_limit $date"
            continue
        fi
        
        handle_port_rules "-A" "$port_range" "ACCEPT"
    done < <(grep -vE '^[[:space:]]*#' "$CONFIG_FILE")

    save_iptables_rules
    log "初始化已完成"
}

save_iptables_rules() {
    log "保存 iptables 规则到 $IPTABLES_SAVE_FILE"
    if ! $IPTABLES_PATH-save > "$IPTABLES_SAVE_FILE.tmp"; then
        log "保存iptables规则失败"
    else
        awk '!seen[$0]++' "$IPTABLES_SAVE_FILE.tmp" > "$IPTABLES_SAVE_FILE"
    fi
    
    log "保存 ip6tables 规则到 $IP6TABLES_SAVE_FILE"
    if ! $IP6TABLES_PATH-save > "$IP6TABLES_SAVE_FILE.tmp"; then
        log "保存ip6tables规则失败" 
    else
        awk '!seen[$0]++' "$IP6TABLES_SAVE_FILE.tmp" > "$IP6TABLES_SAVE_FILE"
    fi
    
    rm -f ./*.tmp
}

restore_iptables_rules() {
    log "从 $IPTABLES_SAVE_FILE 恢复 iptables 规则"
    if [ -f "$IPTABLES_SAVE_FILE" ]; then
        "$IPTABLES_PATH"-restore < "$IPTABLES_SAVE_FILE" || log "IPv4规则恢复失败"
    fi
    
    log "从 $IP6TABLES_SAVE_FILE 恢复 ip6tables 规则"
    if [ -f "$IP6TABLES_SAVE_FILE" ]; then
        "$IP6TABLES_PATH"-restore < "$IP6TABLES_SAVE_FILE" || log "IPv6规则恢复失败"
    fi
}

save_traffic_usage() {
    local traffic_data=""
    local iptables_data=$({
        $IPTABLES_PATH -L PORT_IN -nvx 2>/dev/null
        $IPTABLES_PATH -L PORT_OUT -nvx 2>/dev/null
        $IP6TABLES_PATH -L PORT_IN -nvx 2>/dev/null
        $IP6TABLES_PATH -L PORT_OUT -nvx 2>/dev/null
    })

    while IFS=$' \t' read -r port_range _ _ _extra || [[ -n "$port_range" ]]; do
        port_range=${port_range%$'\r'}
        
        [[ "$port_range" =~ ^[[:space:]]*# || -z "$port_range" ]] && continue
        
        if [[ -n "$_extra" ]]; then
            log "忽略无效行: $port_range $_extra"
            continue
        fi
        
        regex_part=$(echo "$port_range" | sed 's/,/|/g' | sed 's/-/:/')
        
        local in_bytes out_bytes
        in_bytes=$(echo "$iptables_data" | grep -E "dports[[:space:]]+($regex_part)\>" | awk '{sum += $2} END {print sum+0}')
        out_bytes=$(echo "$iptables_data" | grep -E "sports[[:space:]]+($regex_part)\>" | awk '{sum += $2} END {print sum+0}')

        in_bytes=${in_bytes:-0}
        out_bytes=${out_bytes:-0}

        traffic_data+="$port_range $in_bytes $out_bytes"$'\n'
    done < <(grep -vE '^[[:space:]]*#|^$' "$CONFIG_FILE")

    echo "$traffic_data" > "${TRAFFIC_SAVE_FILE}.tmp" && \
        mv -f "${TRAFFIC_SAVE_FILE}.tmp" "$TRAFFIC_SAVE_FILE"

    log "流量统计已保存至 $TRAFFIC_SAVE_FILE（合并 IPv4/IPv6）"
}

convert_scientific_notation() {
    awk -v num="$1" 'BEGIN { printf "%.0f", num }'
}

check_limits() {
    local iptables_output=$({
        $IPTABLES_PATH -L PORT_IN -nvx
        $IPTABLES_PATH -L PORT_OUT -nvx
        $IP6TABLES_PATH -L PORT_IN -nvx
        $IP6TABLES_PATH -L PORT_OUT -nvx
    })

    while IFS=$' \t' read -r port_range limit reset_day _extra || [[ -n "$port_range" ]]; do
        port_range=${port_range%$'\r'}
        limit=${limit%$'\r'}
        reset_day=${reset_day%$'\r'}
        
        [[ "$port_range" =~ ^[[:space:]]*# || -z "$port_range" ]] && continue
        
        if [[ -z "$limit" || -z "$reset_day" || -n "$_extra" ]]; then
            log "配置错误：行 '$port_range $limit $reset_day' 字段不完整"
            continue
        fi

        regex_part=$(echo "$port_range" | sed 's/,/|/g' | sed 's/-/:/')

        local in_bytes out_bytes total_bytes
        in_bytes=$(echo "$iptables_output" | grep -E "dports[[:space:]]+($regex_part)\>" | awk '{sum += $2} END {print sum+0}')
        out_bytes=$(echo "$iptables_output" | grep -E "sports[[:space:]]+($regex_part)\>" | awk '{sum += $2} END {print sum+0}')
        in_bytes=$(convert_scientific_notation "${in_bytes:-0}")
        out_bytes=$(convert_scientific_notation "${out_bytes:-0}")
        total_bytes=$(( in_bytes + out_bytes ))

        local limit_bytes
        limit_bytes=$(echo "$limit * 1024^3" | bc -l)
        limit_bytes=$(convert_scientific_notation "$limit_bytes") 

        log "端口 $port_range: 入站 $in_bytes 字节, 出站 $out_bytes 字节, 总计 $total_bytes 字节, 限制 $limit_bytes 字节"

        if (( total_bytes > limit_bytes )); then
            log "端口 $port_range 超出流量限制 ($limit GiB)，添加阻止规则"
            if echo "$iptables_output" | grep -qE "DROP.*multiport.*($regex_part)(\>|,)"; then
                log "$port_range 已有 DROP 规则，跳过添加"
            else
                if handle_port_rules "-I" "$port_range" "DROP"; then
                    log "已成功添加 $port_range 的 DROP 规则"
                else
                    log "添加 $port_range 的 DROP 规则失败"
                    continue
                fi
            fi
        fi
    done < <(grep -vE '^[[:space:]]*#|^$' "$CONFIG_FILE")
}

show_stats() {
    echo "当前流量使用情况（包含IPv4/IPv6）："

    while IFS=$' \t' read -r port_range limit reset_day _extra || [[ -n "$port_range" ]]; do
        port_range=${port_range%$'\r'}
        limit=${limit%$'\r'}
        reset_day=${reset_day%$'\r'}

        [[ "$port_range" =~ ^[[:space:]]*# || -z "$port_range" ]] && continue

        if [[ -z "$limit" || -z "$reset_day" || -n "$_extra" ]]; then
            echo " [错误] 无效配置行: $port_range $limit $reset_day" >&2
            continue
        fi

        regex_part=$(echo "$port_range" | sed 's/,/|/g' | sed 's/-/:/')

        ipv4_in=$( $IPTABLES_PATH -L PORT_IN -nvx | grep -E "(dports)[[:space:]]+${regex_part}\\b" | awk '{sum+=$2} END{print sum}' )
        ipv4_out=$( $IPTABLES_PATH -L PORT_OUT -nvx | grep -E "(sports)[[:space:]]+${regex_part}\\b" | awk '{sum+=$2} END{print sum}' )

        ipv6_in=$( $IP6TABLES_PATH -L PORT_IN -nvx | grep -E "(dports)[[:space:]]+${regex_part}\\b" | awk '{sum+=$2} END{print sum}' )
        ipv6_out=$( $IP6TABLES_PATH -L PORT_OUT -nvx | grep -E "(sports)[[:space:]]+${regex_part}\\b" | awk '{sum+=$2} END{print sum}' )

        ipv4_in=${ipv4_in:-0}
        ipv4_out=${ipv4_out:-0}
        ipv6_in=${ipv6_in:-0}
        ipv6_out=${ipv6_out:-0}

        ipv4_in=$(convert_scientific_notation "$ipv4_in")
        ipv4_out=$(convert_scientific_notation "$ipv4_out")
        ipv6_in=$(convert_scientific_notation "$ipv6_in")
        ipv6_out=$(convert_scientific_notation "$ipv6_out")

        total_bytes=$(( ipv4_in + ipv4_out + ipv6_in + ipv6_out ))
        total_gb=$(printf "%.2f" "$(echo "scale=2; $total_bytes/1024/1024/1024" | bc)")

        ipv4_rules=$($IPTABLES_PATH -L PORT_IN -n)
        ipv6_rules=$($IP6TABLES_PATH -L PORT_IN -n)
        status="正常"
        if echo "$ipv4_rules $ipv6_rules" | grep -qE "DROP.*multiport.*($regex_part)"; then
            status="已暂停"
        fi

        echo "端口范围 $port_range:"
        echo "  当前使用：$total_gb GiB"
        echo "  月度限制：$limit GiB"
        echo "  重置日期：每月 $reset_day 日"
        echo "  当前状态：$status"
        echo "-------------------"
    done < <(grep -vE '^[[:space:]]*#|^$' "$CONFIG_FILE")
}

save_remaining_limits() {
    local temp_config_file=$(mktemp)
    local port_range original_limit reset_day
    declare -A saved_in saved_out

    if [[ -f "$TRAFFIC_SAVE_FILE" ]]; then
        while IFS= read -r line || [[ -n "$line" ]]; do
            line="${line%%#*}"                
            line=$(echo "$line" | xargs)       
            [[ -z "$line" ]] && continue       

            read -r port in_bytes out_bytes _ <<< "$line"
            if [[ -n "$port" && -n "$in_bytes" && -n "$out_bytes" ]]; then
                saved_in["$port"]=$in_bytes
                saved_out["$port"]=$out_bytes
            else
                log "忽略无效行: $line"
            fi
        done < "$TRAFFIC_SAVE_FILE"
    fi

    while read -r port_range original_limit reset_day; do
        [[ "$port_range" =~ ^#.*$ || -z "$port_range" ]] && continue

        local saved_in_bytes=$(convert_scientific_notation "${saved_in["$port_range"]:-0}")
        local saved_out_bytes=$(convert_scientific_notation "${saved_out["$port_range"]:-0}")
        local total_bytes=$((saved_in_bytes + saved_out_bytes))

        local limit_bytes=$(echo "$original_limit * 1024^3" | bc -l)
        local limit_bytes_rounded=$(convert_scientific_notation "$limit_bytes")
        local remaining_bytes=$(( limit_bytes_rounded - total_bytes ))

        local remaining_gb=$(awk -v rb="$remaining_bytes" 'BEGIN { res=rb/1073741824; printf "%.2f", (res>0)*res }')

        echo "$port_range $remaining_gb $reset_day" >> "$temp_config_file"
    done < "$CONFIG_FILE"

    mv "$temp_config_file" "$CONFIG_FILE"
    log "已更新剩余流量限制（合并IPv4/IPv6流量）"
}

pause_and_clear() {
    log "开始清除由脚本添加的iptables规则"

    for ipt_cmd in "$IPTABLES_PATH" "$IP6TABLES_PATH"; do
        for chain in INPUT OUTPUT; do
            if $ipt_cmd -C "$chain" -j PORT_IN &>/dev/null; then
                $ipt_cmd -D "$chain" -j PORT_IN
            fi
            if $ipt_cmd -C "$chain" -j PORT_OUT &>/dev/null; then
                $ipt_cmd -D "$chain" -j PORT_OUT
            fi
        done
        
        for custom_chain in PORT_IN PORT_OUT; do
            if $ipt_cmd -L "$custom_chain" &>/dev/null; then
                $ipt_cmd -F "$custom_chain"
                $ipt_cmd -X "$custom_chain"
            fi
        done
    done

    local temp_cron=$(mktemp)
    sudo crontab -l 2>/dev/null | grep -v "# rent" > "$temp_cron"
    sudo crontab "$temp_cron"
    rm -f "$temp_cron"
    
    log "iptables规则和cron定时任务已清除."
}

add_cron_tasks() {
    local check_time="${1:-"*/1 * * * *"}"
    local log_time="${2:-"0 0 * * *"}"

    current_cron=$(sudo crontab -l 2>/dev/null)
    
    filtered_cron=$(echo "$current_cron" | grep -v "# rent")

    new_cron=$(cat <<EOF
$filtered_cron
@reboot /usr/local/bin/rent.sh recover # rent
$check_time /usr/local/bin/rent.sh check # rent
$log_time /usr/local/bin/rent.sh clear # rent
EOF
)
    echo "$new_cron" | sudo crontab -
    echo "cron定时任务已添加."
}

add_re_cron_task() {
    local current_cron=$(sudo crontab -l 2>/dev/null)
    local config_file="$CONFIG_FILE"

    validate_port_format() {
        [[ "$1" =~ ^([0-9]+(-[0-9]+)?,)*[0-9]+(-[0-9]+)?$ ]] || {
            echo "错误：端口格式无效，应为端口或范围（如 5201或6001-6010）"
            return 1
        }
    }

    validate_day() {
        [[ "$1" =~ ^[0-9]+$ ]] && (( $1 >= 1 && $1 <= 28 )) || {
            echo "错误：日期必须在1-28之间，已重置为默认值1"
            return 1
        }
    }

    generate_tag() {
        echo "# rent:$1"
    }

    is_task_existing() {
        grep -qF "$1" <<< "$current_cron"
    }

    add_single_task() {
        local port_range=$1
        local day=${2:-1}

        if ! validate_port_format "$port_range"; then
            return 1
        fi

        if ! validate_day "$day" 2>/dev/null; then
            day=1
        fi

        local tag=$(generate_tag "$port_range")
        if is_task_existing "$tag"; then
            echo "警告：端口组 $port_range 的任务已存在，跳过..."
            return 0
        fi

        current_cron+=$'\n'"0 0 $day * * /usr/local/bin/rent.sh reset \"$port_range\" $tag"
        echo "信息：端口组 $port_range 的定时任务已添加（每月${day}日重置流量）"
    }

    parameter_mode() {
        if (( $# == 2 )); then
            add_single_task "$1" "$2" || return 1
        else
            for port in "$@"; do
                add_single_task "$port" 1
            done
        fi
    }

    process_config_file() {
        if [[ ! -f "$config_file" ]]; then
            echo "错误：配置文件 $config_file 不存在"
            return 1
        fi

        while IFS= read -r line || [[ -n "$line" ]]; do
            line=$(echo "$line" | sed -e 's/#.*$//' -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')
            [[ -z "$line" ]] && continue

            local port_range traffic day
            read -r port_range traffic day <<< "$line"

            if [[ -z "$port_range" || -z "$day" ]]; then
                echo "错误：配置文件行格式错误，跳过：$line"
                continue
            fi

            add_single_task "$port_range" "$day"
        done < "$config_file"
    }

    case $# in
        0) process_config_file ;;
        2) parameter_mode "$@" || return $? ;;
        *) parameter_mode "$@" ;;
    esac

    echo "正在更新定时任务配置..."
    sudo crontab <<< "${current_cron#}"
    echo "成功：所有定时任务配置已完成！"
}

delete_iptables_range() { 
    local selected_range="${1}"
    [[ -z "${selected_range}" ]] && {
        echo "请输入要删除的端口 (如: 49364-49365 或 6200):"
        read -r selected_range
    }

    if ! grep -vE '^[[:space:]]*#|^$' "${CONFIG_FILE}" | awk '{print $1}' | grep -Fxq "${selected_range}"; then
        echo "配置文件中不存在端口 ${selected_range}"
        return 1
    fi

    log "删除 iptables 规则 (仅针对 ${selected_range})"

    local tmp_file tmp_cp_file
    tmp_file=$(mktemp) || { echo "创建临时文件失败"; return 1; }
    tmp_cp_file=$(mktemp) || { echo "创建临时文件失败"; return 1; }

    while IFS=$' \t' read -r port_range limit reset_day _extra || [[ -n "$port_range" ]]; do
        port_range=${port_range%$'\r'}
        limit=${limit%$'\r'}
        reset_day=${reset_day%$'\r'}
        
        [[ "${port_range}" =~ ^# || -z "${port_range}" ]] && continue
        
        if [[ -z "$limit" || -z "$reset_day" || -n "$_extra" ]]; then
            log "忽略无效行: $port_range $limit $reset_day $_extra"
            continue
        fi

        if [[ "${port_range}" == "${selected_range}" ]]; then
            handle_port_rules "-D" "${port_range}" "ACCEPT,DROP"
        else
            printf "%s %s %s\n" "${port_range}" "${limit}" "${reset_day}" | tee -a "${tmp_file}" "${tmp_cp_file}" >/dev/null
        fi
    done < <(grep -vE '^[[:space:]]*#|^$' "${CONFIG_FILE}")

    mv "${tmp_file}" "${CONFIG_FILE}" || { echo "配置文件更新失败"; return 1; }
    mv "${tmp_cp_file}" "${CP_FILE}" || { echo "备份文件更新失败"; return 1; }

    save_iptables_rules

    local cron_comment="# rent:${selected_range}"
    (sudo crontab -l 2>/dev/null | grep -vF "${cron_comment}") | sudo crontab - 2>/dev/null

    log "端口 ${selected_range} 的自定义iptables规则及相关定时任务已删除，配置文件已同步"
}

add_iptables_range() {
    local selected_range="${1}"
    if [[ -z "${selected_range}" ]]; then
        echo "请输入要添加的端口 (如: 49364-49365 或 6200):"
        read -r selected_range
    fi

    if [[ -f "${CONFIG_FILE}" ]]; then
        local new_intervals=()
        IFS=',' read -r -a new_segs <<< "${selected_range}"
        for seg in "${new_segs[@]}"; do
            if [[ "$seg" =~ ^([0-9]+)-([0-9]+)$ ]]; then
                new_intervals+=("${BASH_REMATCH[1]}-${BASH_REMATCH[2]}")
            elif [[ "$seg" =~ ^[0-9]+$ ]]; then
                new_intervals+=("$seg-$seg")
            else
                echo "错误：无效的端口格式 ${seg}"
                return 1
            fi
        done

        while IFS= read -r line; do
            [[ "$line" =~ ^[[:space:]]*# || -z "$line" ]] && continue
            local existing_range
            existing_range=$(echo "$line" | awk '{print $1}')
            local existing_intervals=()
            IFS=',' read -r -a ex_segs <<< "${existing_range}"
            for seg in "${ex_segs[@]}"; do
                if [[ "$seg" =~ ^([0-9]+)-([0-9]+)$ ]]; then
                    existing_intervals+=("${BASH_REMATCH[1]}-${BASH_REMATCH[2]}")
                elif [[ "$seg" =~ ^[0-9]+$ ]]; then
                    existing_intervals+=("$seg-$seg")
                fi
            done
            for new_int in "${new_intervals[@]}"; do
                local new_start=${new_int%-*}
                local new_end=${new_int#*-}
                for ex_int in "${existing_intervals[@]}"; do
                    local ex_start=${ex_int%-*}
                    local ex_end=${ex_int#*-}
                    if (( new_start <= ex_end && new_end >= ex_start )); then
                        echo "错误：端口范围 ${selected_range} 与配置中已存在的端口 ${existing_range} 重叠，无法添加"
                        return 1
                    fi
                done
            done
        done < "${CONFIG_FILE}"
    fi

    local reset_day="${2}"
    local regex='^[1-9]$|^1[0-9]$|^2[0-8]$'

    if [[ -z "${reset_day}" ]]; then
        echo "请输入重置日期 (1-28)，无效日期会循环:"
        until [[ "${reset_day}" =~ ${regex} ]]; do
            read -r reset_day
            [[ -n "${reset_day}" ]] || echo "输入不能为空，请重新输入:"
        done
    elif ! [[ "${reset_day}" =~ ${regex} ]]; then
        echo "重置日期无效，请输入一个有效的日期 (1-28)"
        return 1
    fi

    local limit
    until [[ "${limit}" =~ ^[0-9]+(\.[0-9]+)?$ ]]; do
        echo "请输入月度流量限制 (如: 100)，单位GiB:"
        read -r limit
    done

    log "添加 iptables 规则 (端口范围: ${selected_range})"

    if ! handle_port_rules "-A" "${selected_range}" "ACCEPT"; then
        echo "添加 ${selected_range} 端口规则失败"
        return 1
    fi

    echo "${selected_range} ${limit} ${reset_day}" | tee -a "${CONFIG_FILE}" "${CP_FILE}" >/dev/null

    save_iptables_rules
    add_re_cron_task "${selected_range}" "${reset_day}"

    log "端口 ${selected_range} 的iptables规则及定时任务已配置，流量限制${limit}GiB"
}

re_iptables_range() {
    local selected_range="${1}"
    if [[ -z "${selected_range}" ]]; then
        echo "请输入要重置流量的端口 (如: 49364-49365 或 6200):"
        read -r selected_range
    fi

    local tmp_file=$(mktemp)
    
    while IFS=$' \t' read -r port_range limit reset_day _extra || [[ -n "$port_range" ]]; do
        port_range=${port_range%$'\r'}
        limit=${limit%$'\r'}
        reset_day=${reset_day%$'\r'}
        
        [[ "${port_range}" =~ ^#.*$ || -z "${port_range}" ]] && continue
        
        if [[ -z "$limit" || -z "$reset_day" || -n "$_extra" ]]; then
            log "忽略无效行: $port_range $limit $reset_day $_extra"
            continue
        fi

        if [[ "${port_range}" == "${selected_range}" ]]; then
            handle_port_rules "-D" "${port_range}" "ACCEPT,DROP"
        else
            echo "${port_range} ${limit} ${reset_day}" >> "${tmp_file}"
        fi
    done < <(grep -vE '^[[:space:]]*#|^$' "${CONFIG_FILE}")

    mv "${tmp_file}" "${CONFIG_FILE}"

    local cp_tmp=$(mktemp)
    local cp_matched_rule=""
    while IFS= read -r line || [[ -n "$line" ]]; do
        line=${line%$'\r'}
        port_range=$(awk '{print $1}' <<< "$line")
        if [[ "$port_range" == "$selected_range" ]]; then
            cp_matched_rule="$line"
        else
            echo "$line" >> "$cp_tmp"
        fi
    done < "${CP_FILE}"
    if [[ -n "$cp_matched_rule" ]]; then
        mv "$cp_tmp" "${CP_FILE}"
        echo "$cp_matched_rule" | tee -a "${CP_FILE}" "${CONFIG_FILE}" >/dev/null
        read -r matched_port matched_limit matched_day <<< "$cp_matched_rule"
        handle_port_rules "-A" "$matched_port" "ACCEPT"
    else
        rm "$cp_tmp"
        echo "未找到与端口范围 ${selected_range} 匹配的备份规则."
    fi

    save_iptables_rules
    log "已重置端口 ${selected_range} 的流量"
}

update_auto() {
    log "正在检查更新..."
    local tmp_file=$(mktemp)
    local script_url="https://raw.githubusercontent.com/BlackSheep-cry/Rent-PL/main/rent.sh"
    local install_path="/usr/local/bin/rent.sh"

    if ! wget -qO "$tmp_file" "$script_url"; then
        log "错误：无法下载最新版本脚本"
        rm -f "$tmp_file"
        return 1
    fi

    chmod 755 "$tmp_file"
    mv -f "$tmp_file" "$install_path"
    log "脚本已成功更新到最新版本！"
    echo "当前版本：$VERSION => 最新版本：$(grep '^VERSION=' "$install_path" | cut -d'"' -f2)"
}

uninstall_rent() {
    echo "卸载前请先执行该命令停止服务："
    echo "sudo rent.sh cancel"
    echo ""

    read -p "若已执行过上述命令，请输入 Y 确认卸载（其他键取消）: " confirm
    if [[ "$confirm" != "Y" && "$confirm" != "y" ]]; then
        echo "卸载已取消"
        exit 0
    fi

    echo "开始卸载 Rent-PL 服务..."

    config_files=(
        "$CONFIG_FILE"
        "$CP_FILE"
        "$LOG_FILE"
        "$TRAFFIC_SAVE_FILE"
        "$IPTABLES_SAVE_FILE"
        "$IP6TABLES_SAVE_FILE"
        "$WEB_PORT_FILE"
        "$HTML_FILE"
        "$WEB_PID_FILE"
        "$PASSWORD_FILE"
        "$WEB_LOG"
    )
    for file in "${config_files[@]}"; do
        if [ -f "$file" ] && rm -f "$file"; then
            echo "删除相关文件成功"
        else
            echo "相关文件不存在或删除失败"
        fi
    done

    if rm -f /usr/local/bin/rent.sh; then
        echo "已删除脚本文件：/usr/local/bin/rent.sh"
    else
        echo "删除脚本文件失败（可能不存在或权限不足）"
    fi
}

show_usage() {
    cat <<-EOF
	用法: sudo rent.sh {命令选项} [参数]
	
	命令选项:
	  init                     初始化Rent-PL服务
	  restart                  重启Rent-PL服务
	  cancel                   终止Rent-PL服务
	  status                   显示流量使用情况
	  web    <第二参数>        管理网页服务
	  log                      输出日志
	  add    <端口范围> <日期> 添加端口
	  del    <端口范围>        删除端口
	  reset  <端口范围>        重置端口流量
	  check                    流量审查
	  recover                  恢复Rent-PL服务 (用于cron)
	  clear                    清理日志文件
	  update                   更新脚本
	  uninstall                卸载脚本
	EOF
}

show_logs() {
    echo "==== 末尾15条日志 ===="
    tail -n 15 "$LOG_FILE"
}

generate_html() {
    local HTML_TMP_FILE="/tmp/index.tmp"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    cat > "$HTML_TMP_FILE" <<EOF
<!DOCTYPE html>
<html lang='zh'>
<head>
    <meta charset='UTF-8'>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>流量统计 - Rent-PL</title>
    <style>
        body { 
            font-family: Arial, sans-serif; 
            margin: 20px; 
            background: #f5f5f5; 
        }
        .container { 
            max-width: 800px; 
            margin: 0 auto; 
            background: white; 
            padding: 20px; 
            border-radius: 8px; 
            box-shadow: 0 0 15px rgba(0,0,0,0.2);
        }
        h1 { 
            color: #2c3e50; 
            text-align: center; 
            font-size: 28px; 
            text-shadow: 2px 2px 4px rgba(0,0,0,0.1);
        }
        .stats { margin: 20px 0; }
        .stat-item { 
            padding: 10px; 
            border-bottom: 1px solid #eee;
        }
        .stat-item h3 { 
            color: #34495e; 
            font-size: 18px; 
            margin-bottom: 8px;
        }
        .stat-item p { color: #666; margin: 8px 0; }
        .remaining { color: #1E90FF; font-weight: bold; }
        .limit { color: #FFA500; font-weight: bold; }
        .reset-day { color: #27ae60; }
        .progress { 
            height: 25px;
            background: #e0e0e0;
            border-radius: 12px;
            overflow: hidden; 
            border: 1px solid #ddd;
            position: relative;
            width: 100%;
        }
        .progress-bar { 
            height: 100%; 
            transition: width 0.3s;
        }
        .progress-percent {
            position: absolute;
            left: 50%;
            top: 50%;
            transform: translate(-50%, -50%);
            color: white;
            font-weight: bold;
            text-shadow: 1px 1px 2px rgba(0,0,0,0.3);
            font-size: 14px;
            z-index: 2;
            white-space: nowrap;
        }
        .status-active { color: #00c853; }
        .status-paused { color: #d50000; }
        .update-time { text-align: center; color: #888; margin-top: 20px; font-size: 0.9em; }

        @media screen and (max-width: 600px) {
            body { margin: 10px; }
            .container { padding: 15px; }
            h1 { font-size: 24px; }
            .stat-item { padding: 8px; }
            .stat-item h3 { font-size: 16px; }
            .progress-percent { font-size: 12px; }
        }
    </style>
</head>
<body>
    <div class='container'>
        <h1>Rent-PL</h1>
        <div class='stats'>
EOF

    while IFS=$' \t' read -r port_range limit reset_day _extra <&3 &&
          IFS=$' \t' read -r cp_port_range cp_limit cp_reset_day _cp_extra <&4; do
        port_range=${port_range%$'\r'}
        limit=${limit%$'\r'}
        reset_day=${reset_day%$'\r'}
        cp_limit=${cp_limit%$'\r'}

        [[ "$port_range" =~ ^[[:space:]]*# || -z "$port_range" ]] && continue
        [[ -z "$limit" || -z "$reset_day" || -n "$_extra" ]] && continue

        regex_part=$(echo "$port_range" | sed 's/,/|/g; s/-/:/g')

        ipv4_in=$($IPTABLES_PATH -L PORT_IN -nvx 2>/dev/null | grep -E "dports.*($regex_part)\\b" | awk '{sum+=$2} END{print sum+0}')
        ipv4_out=$($IPTABLES_PATH -L PORT_OUT -nvx 2>/dev/null | grep -E "sports.*($regex_part)\\b" | awk '{sum+=$2} END{print sum+0}')
        ipv6_in=$($IP6TABLES_PATH -L PORT_IN -nvx 2>/dev/null | grep -E "dports.*($regex_part)\\b" | awk '{sum+=$2} END{print sum+0}')
        ipv6_out=$($IP6TABLES_PATH -L PORT_OUT -nvx 2>/dev/null | grep -E "sports.*($regex_part)\\b" | awk '{sum+=$2} END{print sum+0}')

        total_bytes=$(($(convert_scientific_notation "$ipv4_in") + \
                      $(convert_scientific_notation "$ipv4_out") + \
                      $(convert_scientific_notation "$ipv6_in") + \
                      $(convert_scientific_notation "$ipv6_out")))

        used_gb=$(awk "BEGIN { printf \"%.2f\", $total_bytes / 1073741824 }")
        limit_gb=$(awk "BEGIN { printf \"%.2f\", $limit }")
        remaining_gb=$(awk "BEGIN { r = $limit_gb - $used_gb; printf \"%.2f\", r < 0 ? 0 : r }")
        limit_gb_display=$(awk "BEGIN { printf \"%.2f\", $cp_limit }")

        if $IPTABLES_PATH -L PORT_IN -n 2>/dev/null | grep -qE "DROP.*($regex_part)" ||
           $IP6TABLES_PATH -L PORT_IN -n 2>/dev/null | grep -qE "DROP.*($regex_part)"; then
            status="已暂停"
            status_class="status-paused"
        else
            status="正常"
            status_class="status-active"
        fi

        if [[ "$cp_limit" =~ ^[0-9.]+$ ]] && (( $(echo "$cp_limit > 0" | bc -l) )); then
            progress=$(awk "BEGIN { p = ($remaining_gb / $cp_limit) * 100; p = (p < 0 ? 0 : p); printf \"%.0f\", p }")
            if (( progress > 0 && progress < 5 )); then progress=5; fi
            (( progress > 100 )) && progress=100
        else
            progress=0
        fi

        if [[ $progress -ge 70 ]]; then
            bar_color="#4CAF50"
        elif [[ $progress -ge 30 ]]; then
            bar_color="#ffa500"
        else
            bar_color="#ff4444"
        fi

        cat <<EOF >> "$HTML_TMP_FILE"
            <div class="stat-item">
                <h3>端口: ${port_range}</h3>
                <p>剩余流量: <span class="remaining">${remaining_gb}</span> GiB / 限额: <span class="limit">${limit_gb_display}</span> GiB</p>
                <div class="progress">
                    <div class="progress-bar" style="width: ${progress}%; background-color: ${bar_color};"></div>
                    <span class="progress-percent">${progress}%</span>
                </div>
                <p>重置日期: 每月 <span class="reset-day">${reset_day}</span> 日 | 状态: <span class="${status_class}">${status}</span></p>
            </div>
EOF
    done 3< <(grep -vE '^[[:space:]]*#|^$' "$CONFIG_FILE") 4< <(grep -vE '^[[:space:]]*#|^$' "$CP_FILE")

    cat >> "$HTML_TMP_FILE" <<EOF
        </div>
        <div class="update-time">最后更新: ${timestamp}</div>
    </div>
</body>
</html>
EOF

    mv -f "$HTML_TMP_FILE" "$HTML_FILE"
}

web_server() {
    local port=${1:-8080}
    generate_html

    if [ ! -f "$PASSWORD_FILE" ]; then
        log "未检测到密码文件，请先设置访问密码"
        init_password || return 1
    fi

    stored_pass=$(awk -F: '/^rent:/{print $2}' "$PASSWORD_FILE")
    export STORED_PASS="$stored_pass"

    python3 -u -c "
from http.server import HTTPServer, BaseHTTPRequestHandler
from base64 import b64decode
import subprocess
import time
import os
import traceback

class DynamicAuthHandler(BaseHTTPRequestHandler):
    last_update = 0
    cached_html = None
    
    def do_GET(self):
        try:
            if self.path == '/favicon.ico':
                self.send_response(404)
                self.end_headers()
                return

            print(f'收到请求: {self.path}')
            auth = self.headers.get('Authorization', '')
            if not auth.startswith('Basic '):
                self.send_auth_challenge()
                return
            
            try:
                creds = b64decode(auth.split(' ')[1]).decode('utf-8')
                username, password = creds.split(':', 1)
            except Exception as auth_error:
                print(f'认证解析失败: {auth_error}')
                self.send_auth_challenge()
                return
            
            stored_pass = os.environ.get('STORED_PASS', '')
            if username != 'rent' or password != stored_pass:
                print('密码验证失败')
                self.send_auth_challenge()
                return

            current_time = time.time()
            if current_time - DynamicAuthHandler.last_update > 3:
                self.update_html()
                DynamicAuthHandler.last_update = current_time

            if not DynamicAuthHandler.cached_html:
                self.send_error(503, 'Service Unavailable')
                return
                
            self.send_response(200)
            self.send_header('Content-type', 'text/html; charset=utf-8')
            self.send_header('Content-Length', str(len(DynamicAuthHandler.cached_html)))
            self.end_headers()
            self.wfile.write(DynamicAuthHandler.cached_html)
            
        except Exception as e:
            print(f'处理请求异常: {traceback.format_exc()}')
            self.send_error(503, 'Internal Server Error')

    def update_html(self):
        try:
            print('正在生成HTML文件...')
            subprocess.check_call(
                ['/usr/local/bin/rent.sh', 'generate_html'],
                stderr=subprocess.STDOUT
            )
            with open('/var/www/index.html', 'rb') as f:
                DynamicAuthHandler.cached_html = f.read()
            print('HTML更新成功')
        except Exception as e:
            print(f'生成HTML失败: {str(e)}')
            DynamicAuthHandler.cached_html = '<h1>系统维护中</h1>'.encode('utf-8')

    def send_auth_challenge(self):
        self.send_response(401)
        realm = 'Rent流量监控'.encode('utf-8').decode('latin-1', errors='replace')
        self.send_header('WWW-Authenticate', f'Basic realm=\"{realm}\"')
        self.end_headers()
        self.wfile.write('401 - 需要身份验证'.encode('utf-8'))

    def log_message(self, format, *args):
        pass

    def log_error(self, format, *args):
        message = format % args
        print(f'服务端错误: {message}')

server = HTTPServer(('0.0.0.0', $port), DynamicAuthHandler)
try:
    server.serve_forever()
except KeyboardInterrupt:
    print('服务正常终止')
    server.server_close()
" > "$WEB_LOG" 2>&1 &

    local pid=$!
    echo $pid > "$WEB_PID_FILE"
    echo "服务已启动(PID: $pid)"
}

manage_web_service() {
    case $1 in
        start)
            if [ -f "$WEB_PID_FILE" ]; then
                pid=$(cat "$WEB_PID_FILE")
                if ps -p $pid > /dev/null; then
                    echo "Web服务已在运行中 (PID: $pid)"
                    return 1
                fi
            fi
            local port=$(get_web_port)
            log "正在启动Web服务，端口：$port"
            web_server $port
            ;;
        stop)
            log "正在停止Web服务..."
            if [ -f "$WEB_PID_FILE" ]; then
                main_pid=$(head -n1 "$WEB_PID_FILE")
                if ps -p $main_pid >/dev/null; then
                    pgid=$(ps -o pgid= $main_pid | tr -d ' ')
                    kill -TERM -- -$pgid 2>/dev/null
                    sleep 0.5
                    kill -KILL -- -$pgid 2>/dev/null
                fi
            fi
            pkill -f "python3 -m http.server.*$(get_web_port)"
            rm -f "$WEB_PID_FILE"
            log "Web服务已停止"
            ;;
        port)
            read -p "请输入新的Web端口 (默认: 8080): " new_port
            new_port=${new_port:-8080}
            if [[ ! "$new_port" =~ ^[0-9]+$ ]] || (( new_port < 1 || new_port > 65535 )); then
                log "错误：端口号无效"
                return 1
            fi
            echo "$new_port" > "$WEB_PORT_FILE"
            manage_web_service stop
            manage_web_service start
            ;;
        password)
            change_password
            manage_web_service stop
            manage_web_service start
            ;;
        *)
            echo "用法: sudo rent.sh web {start|stop|port|password}"
            ;;
    esac
}

get_web_port() {
    if [ -f "$WEB_PORT_FILE" ] && [[ $(cat "$WEB_PORT_FILE") =~ ^[0-9]+$ ]]; then
        cat "$WEB_PORT_FILE"
    else
        echo "8080"
    fi
}

init_password() {
    read -p "设置 rent 用户密码: " password
    echo "rent:$password" > "$PASSWORD_FILE"
    chmod 600 "$PASSWORD_FILE"
    log "密码设置成功 (用户名固定为rent)"
}

change_password() {
    if [ ! -f "$PASSWORD_FILE" ]; then
        log "首次使用请设置密码"
        init_password
        return $?
    fi

    read -p "输入旧密码: " old_pass
    stored_pass=$(awk -F: '/^rent:/{print $2}' "$PASSWORD_FILE")
    
    if [ "$old_pass" != "$stored_pass" ]; then
        log "旧密码验证失败"
        return 1
    fi
    
    read -p "输入新密码: " new_pass
    echo "rent:$new_pass" > "$PASSWORD_FILE"
    log "密码已更新"
}

case "$1" in
    init)
        log "初始化Rent-PL服务"
        cp "$CP_FILE" "$CONFIG_FILE"
        initialize_iptables
        > "$TRAFFIC_SAVE_FILE"
        add_cron_tasks
        add_re_cron_task
        manage_web_service start
        ;;
    restart)
        log "重启Rent-PL服务 (请先使用cancel)"
        restore_iptables_rules
        save_remaining_limits
        add_cron_tasks
        add_re_cron_task
        manage_web_service start
        ;;
    cancel)
        log "终止Rent-PL服务"
        save_traffic_usage
        save_iptables_rules
        pause_and_clear
        manage_web_service stop
        ;;
    status)
        show_stats
        ;;
    web)
        manage_web_service "$2"
        ;;
    log)
        show_logs
        ;;
    add)
        add_iptables_range "$2" "$3"
        ;;
    del)
        delete_iptables_range "$2"
        ;;
    delete)
        delete_iptables_range "$2"
        ;;
    reset)
        re_iptables_range "$2"
        ;;
    check)
        check_limits
        save_traffic_usage
        save_iptables_rules
        ;;
    recover)
        log "恢复Rent-PL服务"
        restore_iptables_rules
        save_remaining_limits
        manage_web_service start
        ;;
    clear)
        clear_log
        ;;
    update)
        update_auto
        ;;
    uninstall)
        uninstall_rent
        ;;
    generate_html)
        generate_html
        ;;
    *)
        show_usage
        exit 1
        ;;
esac

exit 0
