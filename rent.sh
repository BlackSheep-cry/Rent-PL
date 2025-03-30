#!/bin/bash

VERSION="V0.5.0"
IPTABLES_PATH="/usr/sbin/iptables"
IP6TABLES_PATH="/usr/sbin/ip6tables"
CONFIG_FILE="/etc/rent/config"
CP_FILE="/etc/rent/config.original"
LOG_FILE="/var/log/rent.log"
TRAFFIC_SAVE_FILE="/var/log/rent_usage.dat"
IPTABLES_SAVE_FILE="/etc/iptables/rent_rules.v4"
IP6TABLES_SAVE_FILE="/etc/iptables/rent_rules.v6"
MAX_LOG_SIZE=262144

mkdir -p /etc/rent /etc/iptables

touch "$TRAFFIC_SAVE_FILE" "$IPTABLES_SAVE_FILE" "$IP6TABLES_SAVE_FILE" "$LOG_FILE"

if [ ! -f "$CONFIG_FILE" ]; then
    cat > "$CONFIG_FILE" << EOF
# 配置格式1：         单端口         月度流量限制(GiB) 重置日期(1-28)
# 配置格式2：起始端口-结束端口 月度流量限制(GiB) 重置日期(1-28)
# 例如：
# 9300 50.20 1
# 49364-49365 100.00 12
EOF
fi

clear_log() {
    if [ -f "$LOG_FILE" ] && [ "$(stat -c %s "$LOG_FILE")" -gt "$MAX_LOG_SIZE" ]; then
        > "$LOG_FILE"
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] 日志文件已自动清空" >> "$LOG_FILE"
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
    local start_port end_port

    IFS=- read -r start_port end_port <<< "$range"
    end_port=${end_port:-$start_port}

    if [[ "$start_port" =~ ^[0-9]+$ && "$end_port" =~ ^[0-9]+$ ]] && (( start_port <= end_port )); then
        echo "$start_port $end_port"
    else
        log "错误，端口格式无效"
        exit 1
    fi
}

handle_port_rules() {
    local action="${1}"
    local port_range="${2}"
    local targets="${3:-DROP}"

    read -r start_port end_port <<< "$(parse_port_range "${port_range}")"
    if [[ ! "${start_port}" =~ ^[0-9]+$ ]] || [[ ! "${end_port}" =~ ^[0-9]+$ ]] || (( start_port > end_port )); then
        log "PORT_ERROR: ${port_range}" >&2
        return 1
    fi

    local port_spec=$([[ "${start_port}" -eq "${end_port}" ]] && echo "${start_port}" || echo "${start_port}:${end_port}")

    process_rule() {
        local chain="$1"
        local ports_flag="$2"
        
        for ipt_cmd in "$IPTABLES_PATH" "$IP6TABLES_PATH"; do
            for proto in tcp udp; do
                for target in "${target_list[@]}"; do
                    if "$ipt_cmd" -C "$chain" -p "${proto}" --match multiport "${ports_flag}" "${port_spec}" -j "${target}" 2>/dev/null; then
                        if [[ "${action}" = "-D" ]]; then
                            "$ipt_cmd" -D "$chain" -p "${proto}" --match multiport "${ports_flag}" "${port_spec}" -j "${target}"
                        fi
                    else
                        if [[ "${action}" = "-A" || "${action}" = "-I" ]]; then
                            "$ipt_cmd" "${action}" "$chain" -p "${proto}" --match multiport "${ports_flag}" "${port_spec}" -j "${target}"
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

    while read -r port_range limit reset_day; do
        [[ "${port_range}" =~ ^#|^$ ]] && continue

        if handle_port_rules "-A" "${port_range}" "ACCEPT"; then
            log "已添加端口规则: ${port_range}"
        else
            log "无效端口格式: ${port_range}，已跳过" >&2
        fi
    done < "${CONFIG_FILE}"

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

    while IFS= read -r line || [[ -n "$line" ]]; do
        line="${line%%#*}"
        line=$(tr -s '[:space:]' <<< "$line" | xargs)
        [ -z "$line" ] && continue

        read -r port_range _ _ <<< "$line"

        local start_port end_port regex_part
        if [[ "$port_range" =~ - ]]; then
            read -r start_port end_port <<< "$(parse_port_range "$port_range")"
            regex_part="$start_port:$end_port|$port_range"
        else
            regex_part="$port_range"
        fi

        local in_bytes out_bytes
        in_bytes=$(echo "$iptables_data" | grep -E "dports[[:space:]]+($regex_part)\>" | awk '{sum += $2} END {print sum+0}')
        out_bytes=$(echo "$iptables_data" | grep -E "sports[[:space:]]+($regex_part)\>" | awk '{sum += $2} END {print sum+0}')

        traffic_data+="$port_range $in_bytes $out_bytes"$'\n'
    done < <(grep -v '^[[:space:]]*#' "$CONFIG_FILE")

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

    while read -r port_range limit reset_day; do
        [[ "$port_range" =~ ^#.*$ || -z "$port_range" ]] && continue

        local start_port end_port regex_part
        if [[ "$port_range" =~ - ]]; then
            read -r start_port end_port <<< "$(parse_port_range "$port_range")"
            regex_part="$start_port:$end_port|$port_range"
        else
            regex_part="$port_range"
        fi

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

            if handle_port_rules "-I" "$port_range" "DROP"; then
                log "已成功添加 $port_range 的 DROP 规则"
            else
                log "添加 $port_range 的 DROP 规则失败"
                continue
            fi

            log "流量超出限制，相应端口服务已暂停"
        fi
    done < "$CONFIG_FILE"
}

show_stats() { 
    echo "当前流量使用情况（包含IPv4/IPv6）："

    local iptables_in_out=$({
        $IPTABLES_PATH -L PORT_IN -nvx
        $IPTABLES_PATH -L PORT_OUT -nvx
        $IP6TABLES_PATH -L PORT_IN -nvx
        $IP6TABLES_PATH -L PORT_OUT -nvx
    })
    local port_limit_rules=$({
        $IPTABLES_PATH -L PORT_IN -n
        $IP6TABLES_PATH -L PORT_IN -n
        $IPTABLES_PATH -L PORT_OUT -n
        $IP6TABLES_PATH -L PORT_OUT -n
    })
    
    while read -r port_range limit reset_day; do
        [[ "$port_range" =~ ^#.*$ || -z "$port_range" ]] && continue

        local port_spec
        if [[ "$port_range" =~ - ]]; then
            read -r start_port end_port <<< "$(parse_port_range "$port_range")"
            port_spec="$start_port:$end_port"
        else
            port_spec="$port_range"
        fi

        local in_bytes out_bytes
        eval $(echo "$iptables_in_out" | grep -E "(dports|sports)[[:space:]]+${port_spec}\\b" | awk '
            /dports/ { in_sum += $2 }
            /sports/ { out_sum += $2 }
            END { printf "in_bytes=%d out_bytes=%d", in_sum+0, out_sum+0 }'
        )

        in_bytes=$(convert_scientific_notation "$in_bytes")
        out_bytes=$(convert_scientific_notation "$out_bytes")
        local total_gb=$(printf "%.2f" $(echo "scale=2; ($in_bytes + $out_bytes)/1024/1024/1024" | bc))

        local status="正常"
        if echo "$port_limit_rules" | grep -q "DROP.*multiport sports $port_spec"; then
            status="已暂停"
        fi

        echo "端口范围 $port_range:"
        echo "  当前使用：$total_gb GiB"
        echo "  月度限制：$limit GiB"
        echo "  重置日期：每月 $reset_day 日"
        echo "  当前状态：$status"
        echo "-------------------"
    done < "$CONFIG_FILE"
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
    
    echo "iptables规则和cron定时任务已清除."
}

add_cron_tasks() {
    local check_time="${1:-"*/1 * * * *"}"
    local log_time="${2:-"0 0 * * *"}"

    current_cron=$(sudo crontab -l 2>/dev/null)
    
    filtered_cron=$(echo "$current_cron" | grep -v "# rent")

    new_cron=$(cat <<EOF
$filtered_cron
@reboot /usr/local/bin/rent.sh recover # rent
$check_time /usr/local/bin/rent.sh check >> /var/log/rent_cron.log 2>&1 # rent
$log_time /usr/local/bin/rent.sh clear # rent
EOF
)
    echo "$new_cron" | sudo crontab -
    echo "cron定时任务已添加."
}

add_re_cron_task() {
    local current_cron=$(sudo crontab -l 2>/dev/null)

    validate_port_format() {
        [[ "$1" =~ ^[0-9]+(-[0-9]+)?$ ]] || {
            echo "错误：端口格式无效，应为单个端口（如6200）或范围（如49364-49365）"; return 1
        }
    }

    validate_day() {
        [[ "$1" =~ ^[0-9]+$ ]] && (( $1 >= 1 && $1 <= 28 )) || {
            echo "错误：日期必须在1-28之间，已重置为默认值1"; return 1
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
            echo "警告：端口 $port_range 的任务已存在，跳过..."
            return 0
        fi

        current_cron+=$'\n'"0 0 $day * * /usr/local/bin/rent.sh reset $port_range $tag"
        echo "信息：端口 $port_range 的定时任务已添加（每月${day}日重置）"
    }

    interactive_mode() {
        while :; do
            read -r -p "请输入要添加的端口（格式：6200 或 49364-49365，输入 done 结束）: " port_range
            [[ "$port_range" == "done" ]] && break
            [[ -z "$port_range" ]] && { echo "错误：输入不能为空"; continue; }
            
            read -r -p "请输入流量重置日期（1-28，默认1）: " day
            add_single_task "$port_range" "$day"
        done
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

    case $# in
        0) interactive_mode ;;
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

    log "删除 iptables 规则 (仅针对 ${selected_range})"

    local tmp_file tmp_cp_file
    tmp_file=$(mktemp) || { echo "创建临时文件失败"; return 1; }
    tmp_cp_file=$(mktemp) || { echo "创建临时文件失败"; return 1; }

    while read -r port_range limit reset_day; do
        [[ "${port_range}" =~ ^# || -z "${port_range}" ]] && continue

        if [[ "${port_range}" == "${selected_range}" ]]; then
            handle_port_rules "-D" "${port_range}" "ACCEPT,DROP"
        else
            printf "%s %s %s\n" "${port_range}" "${limit}" "${reset_day}" | tee -a "${tmp_file}" "${tmp_cp_file}" >/dev/null
        fi
    done < "${CONFIG_FILE}"

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

    if [[ -f "${CONFIG_FILE}" ]] && grep -q "^${selected_range} " "${CONFIG_FILE}" 2>/dev/null; then
        echo "错误：端口范围 ${selected_range} 已存在，无法重复添加。"
        return 1
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
        echo "无效的端口格式: ${selected_range}"
        return 1
    fi

    printf "%s %s %s\n" "${selected_range}" "${limit}" "${reset_day}" \
        | tee -a "${CONFIG_FILE}" "${CP_FILE}" >/dev/null

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
    
    while read -r port_range limit reset_day; do
        [[ "${port_range}" =~ ^#.*$ || -z "${port_range}" ]] && continue

        if [[ "${port_range}" == "${selected_range}" ]]; then
            handle_port_rules "-D" "${port_range}" "ACCEPT,DROP"
        else
            echo "${port_range} ${limit} ${reset_day}" >> "${tmp_file}"
        fi
    done < "${CONFIG_FILE}"

    mv "${tmp_file}" "${CONFIG_FILE}"

    local matched_rule=$(awk -v sr="${selected_range}" '$1 == sr {print $0; exit}' "${CP_FILE}")
    if [[ -n "${matched_rule}" ]]; then
        read -r matched_port matched_limit matched_day <<< "${matched_rule}"
        handle_port_rules "-A" "${matched_port}" "ACCEPT"
        echo "${matched_rule}" >> "${CONFIG_FILE}"
    else
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

    if ! bash -n "$tmp_file"; then
        log "错误：下载的脚本语法验证失败"
        rm -f "$tmp_file"
        return 1
    fi

    chmod 755 "$tmp_file"
    mv -f "$tmp_file" "$install_path"
    log "脚本已成功更新到最新版本！"
    echo "当前版本：$VERSION => 最新版本：$(grep '^VERSION=' "$install_path" | cut -d'"' -f2)"
}

uninstall_rent() {
    echo "卸载前请先执行该命令停止服务：sudo rent.sh cancel"
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
	  log                      输出日志
	  add    <端口范围> <日期> 添加端口
	  del    <端口范围>        删除端口
	  reset  <端口范围>        重置端口流量
	  check                    流量审查
	  recover                  恢复Rent-PL服务（用于cron）
	  clear                    清理日志文件
	  update                   更新脚本
	  uninstall                卸载脚本
	EOF
}

show_logs() {
    echo "==== 末尾15条日志 ===="
    tail -n 15 "$LOG_FILE"
}

case "$1" in
    init)
        log "初始化Rent-PL服务"
        cp "$CP_FILE" "$CONFIG_FILE"
        initialize_iptables
        > "$TRAFFIC_SAVE_FILE"
        add_cron_tasks
        add_re_cron_task
        ;;
    restart)
        log "重启Rent-PL服务"
        restore_iptables_rules
        save_remaining_limits
        add_cron_tasks
        add_re_cron_task
        ;;
    cancel)
        log "终止Rent-PL服务"
        save_traffic_usage
        save_iptables_rules
        pause_and_clear
        ;;
    status)
        show_stats
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
    *)
        show_usage
        exit 1
        ;;
esac

exit 0
