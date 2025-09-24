#!/bin/bash

# OpenHands GUI Background Launcher for Apple Silicon Macs (M1/M2/M3/M4/M5+)
# Tested on M1 MacBook running macOS Sequoia 15.7
# Based on proven working solution from GitHub issue #7618
# Enhanced with security improvements and best practices

set -euo pipefail

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Configuration
OPENHANDS_URL="${OPENHANDS_URL:-http://localhost:3000}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_FILE="$SCRIPT_DIR/openhands.log"
PID_FILE="$SCRIPT_DIR/openhands.pid"

# Security configuration
CONTAINER_NAME="${OPENHANDS_CONTAINER_NAME:-openhands-app}"
RUNTIME_IMAGE="${OPENHANDS_RUNTIME_IMAGE:-docker.all-hands.dev/all-hands-ai/runtime:0.57.0-nikolaik}"
MAIN_IMAGE="${OPENHANDS_MAIN_IMAGE:-docker.all-hands.dev/all-hands-ai/openhands:0.57.0}"
MAX_LOG_SIZE="${MAX_LOG_SIZE:-10485760}"  # 10MB
SECURITY_TIMEOUT="${SECURITY_TIMEOUT:-300}"  # 5 minutes

# Security functions
function log_security_event() {
    local event_type="$1"
    local message="$2"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [SECURITY] [$event_type] $message" >> "$SCRIPT_DIR/security.log"
}

function validate_environment() {
    # Check for suspicious environment variables
    local suspicious_vars=()
    for var in $(env | grep -E '(PASSWORD|SECRET|KEY|TOKEN)' | cut -d= -f1); do
        if [[ "$var" =~ ^(OPENHANDS_|SANDBOX_|DOCKER_) ]]; then
            suspicious_vars+=("$var")
        fi
    done
    
    if [ ${#suspicious_vars[@]} -gt 0 ]; then
        log_security_event "WARNING" "Suspicious environment variables detected: ${suspicious_vars[*]}"
        echo -e "${YELLOW}⚠️  Warning: Potentially sensitive environment variables detected${NC}"
    fi
}

function secure_file_permissions() {
    # Ensure log and pid files have secure permissions
    touch "$LOG_FILE" "$PID_FILE" 2>/dev/null || true
    chmod 600 "$LOG_FILE" "$PID_FILE" 2>/dev/null || true
    touch "$SCRIPT_DIR/security.log" 2>/dev/null || true
    chmod 600 "$SCRIPT_DIR/security.log" 2>/dev/null || true
}

function validate_docker_socket() {
    local socket_path="/var/run/docker.sock"
    if [ -S "$socket_path" ]; then
        local socket_perms=$(stat -c "%a" "$socket_path" 2>/dev/null || echo "000")
        if [[ "$socket_perms" =~ ^[0-7]*[6-7][0-7]*$ ]]; then
            log_security_event "WARNING" "Docker socket has group/world writable permissions: $socket_perms"
            echo -e "${YELLOW}⚠️  Warning: Docker socket has insecure permissions${NC}"
        fi
    fi
}

# Load environment variables if available
if [ -f "$HOME/.openhands_env" ]; then
    if [ -r "$HOME/.openhands_env" ]; then
        source "$HOME/.openhands_env"
        log_security_event "INFO" "Loaded environment configuration from ~/.openhands_env"
    else
        echo -e "${RED}❌ Error: ~/.openhands_env exists but is not readable${NC}"
        exit 1
    fi
fi

# Initialize security
validate_environment
secure_file_permissions
validate_docker_socket

function show_usage() {
    echo -e "${BLUE}OpenHands GUI Background Launcher (Security Enhanced)${NC}"
    echo ""
    echo "Usage: $0 [start|start-browser|stop|restart|status|logs|security]"
    echo ""
    echo "Commands:"
    echo "  start         - Start OpenHands in background (no browser)"
    echo "  start-browser - Start OpenHands in background and open browser"
    echo "  stop          - Stop OpenHands and cleanup containers"
    echo "  restart       - Restart OpenHands"
    echo "  status        - Check if OpenHands is running"
    echo "  logs          - Show recent logs and security events"
    echo "  security      - Show security information and audit log"
    echo ""
    echo "Security Environment Variables:"
    echo "  OPENHANDS_CONTAINER_NAME   - Container name (default: openhands-app)"
    echo "  OPENHANDS_MEMORY_LIMIT     - Memory limit (default: 4g)"
    echo "  OPENHANDS_CPU_LIMIT        - CPU limit (default: 2.0)"
    echo "  LOG_ALL_EVENTS             - Enable verbose logging (default: false)"
    echo ""
    echo "Security Features:"
    echo "  - Container resource limits"
    echo "  - Read-only filesystem with tmpfs mounts"
    echo "  - Capability dropping (least privilege)"
    echo "  - Security event logging"
    echo "  - Environment variable validation"
    echo ""
}

function check_docker() {
    if ! docker info >/dev/null 2>&1; then
        echo -e "${RED}❌ Docker is not running. Starting Colima...${NC}"
        log_security_event "INFO" "Starting Colima Docker runtime"
        colima start --cpu 2 --memory 4 --disk 30
        sleep 5
        
        # Verify Docker started successfully
        if ! docker info >/dev/null 2>&1; then
            log_security_event "ERROR" "Failed to start Docker/Colima"
            echo -e "${RED}❌ Failed to start Docker/Colima${NC}"
            exit 1
        fi
    fi
}

function wait_for_openhands() {
    echo -e "${YELLOW}⏳ Waiting for OpenHands to start...${NC}"
    
    for i in {1..30}; do
        if curl -s "$OPENHANDS_URL" >/dev/null 2>&1; then
            echo -e "${GREEN}✅ OpenHands is ready!${NC}"
            return 0
        fi
        sleep 2
        echo -n "."
    done
    
    echo -e "${RED}❌ OpenHands failed to start within 60 seconds${NC}"
    return 1
}

function start_openhands() {
    local open_browser=${1:-false}
    
    if is_running; then
        echo -e "${YELLOW}⚠️  OpenHands is already running at $OPENHANDS_URL${NC}"
        log_security_event "INFO" "OpenHands already running, start request ignored"
        if [ "$open_browser" = "true" ]; then
            open "$OPENHANDS_URL"
        fi
        return 0
    fi
    
    echo -e "${BLUE}🚀 Starting OpenHands GUI with Apple Silicon optimizations...${NC}"
    log_security_event "INFO" "Starting OpenHands container"
    
    check_docker
    
    # Clean up only OpenHands-related containers (safer than prune)
    cleanup_openhands_containers
    
    # Set platform for Apple Silicon (ARM64) compatibility
    export DOCKER_DEFAULT_PLATFORM=linux/amd64
    log_security_event "INFO" "Set Docker platform to linux/amd64"
    
    # Validate images exist before starting
    if ! docker image inspect "$MAIN_IMAGE" >/dev/null 2>&1; then
        echo -e "${BLUE}📥 Pulling OpenHands image...${NC}"
        docker pull "$MAIN_IMAGE"
        log_security_event "INFO" "Pulled main image: $MAIN_IMAGE"
    fi
    
    if ! docker image inspect "$RUNTIME_IMAGE" >/dev/null 2>&1; then
        echo -e "${BLUE}📥 Pulling runtime image...${NC}"
        docker pull "$RUNTIME_IMAGE"
        log_security_event "INFO" "Pulled runtime image: $RUNTIME_IMAGE"
    fi
    
    # Start OpenHands in background with security constraints
    local container_id
    container_id=$(docker run -d --pull=always \
        --name "$CONTAINER_NAME" \
        --memory "${OPENHANDS_MEMORY_LIMIT:-4g}" \
        --cpus "${OPENHANDS_CPU_LIMIT:-2.0}" \
        --read-only \
        --tmpfs /tmp \
        --tmpfs /run \
        --security-opt no-new-privileges \
        --cap-drop ALL \
        --cap-add CHOWN \
        --cap-add DAC_OVERRIDE \
        --cap-add FOWNER \
        --cap-add NET_BIND_SERVICE \
        -e SANDBOX_RUNTIME_CONTAINER_IMAGE="$RUNTIME_IMAGE" \
        -e LOG_ALL_EVENTS="${LOG_ALL_EVENTS:-false}" \
        -e BROWSER_ACTION_ENABLED=false \
        -v /var/run/docker.sock:/var/run/docker.sock:ro \
        -v "$HOME/.openhands:/.openhands" \
        -p 3000:3000 \
        --add-host host.docker.internal:host-gateway \
        "$MAIN_IMAGE")
    
    if [ -n "$container_id" ]; then
        log_security_event "INFO" "Started container: $container_id"
        echo "$container_id" > "$PID_FILE"
    else
        log_security_event "ERROR" "Failed to start container"
        echo -e "${RED}❌ Failed to start OpenHands container${NC}"
        exit 1
    fi
    
    if wait_for_openhands; then
        if [ "$open_browser" = "true" ]; then
            echo -e "${GREEN}🌐 Opening browser...${NC}"
            open "$OPENHANDS_URL"
        fi
        echo -e "${GREEN}✅ OpenHands is running in background${NC}"
        echo -e "${BLUE}🌐 UI available at: $OPENHANDS_URL${NC}"
        echo -e "${BLUE}📝 Logs: docker logs -f $CONTAINER_NAME${NC}"
        echo -e "${BLUE}🛑 Stop: $0 stop${NC}"
        log_security_event "INFO" "OpenHands started successfully"
    else
        log_security_event "ERROR" "OpenHands failed to start within timeout"
        stop_openhands
        exit 1
    fi
}

function cleanup_openhands_containers() {
    # Clean up only OpenHands-related containers (safer than prune)
    echo -e "${YELLOW}🧩 Cleaning up OpenHands containers...${NC}"
    
    # Stop and remove main container if it exists
    if docker ps -a --format "{{.Names}}" | grep -q "^${CONTAINER_NAME}$"; then
        docker stop "$CONTAINER_NAME" 2>/dev/null || true
        docker rm "$CONTAINER_NAME" 2>/dev/null || true
        log_security_event "INFO" "Cleaned up main container: $CONTAINER_NAME"
    fi
    
    # Clean up OpenHands runtime containers (they have random names but use the runtime image)
    RUNTIME_CONTAINERS=$(docker ps -a --filter "ancestor=$RUNTIME_IMAGE" --format "{{.ID}}" 2>/dev/null || true)
    if [ -n "$RUNTIME_CONTAINERS" ]; then
        echo "$RUNTIME_CONTAINERS" | xargs -r docker rm -f 2>/dev/null || true
        log_security_event "INFO" "Cleaned up runtime containers"
    fi
}

function stop_openhands() {
    echo -e "${YELLOW}🛑 Stopping OpenHands...${NC}"
    log_security_event "INFO" "Stopping OpenHands"
    
    # Stop main OpenHands container
    if docker ps --format "{{.Names}}" | grep -q "^${CONTAINER_NAME}$"; then
        docker stop "$CONTAINER_NAME" 2>/dev/null || true
        docker rm "$CONTAINER_NAME" 2>/dev/null || true
        log_security_event "INFO" "Stopped main container: $CONTAINER_NAME"
    fi
    
    # Clean up OpenHands runtime containers
    echo -e "${YELLOW}🧩 Cleaning up runtime containers...${NC}"
    RUNTIME_CONTAINERS=$(docker ps -a --filter "ancestor=$RUNTIME_IMAGE" --format "{{.ID}}" 2>/dev/null || true)
    if [ -n "$RUNTIME_CONTAINERS" ]; then
        echo "$RUNTIME_CONTAINERS" | xargs -r docker rm -f 2>/dev/null || true
        log_security_event "INFO" "Cleaned up runtime containers"
    fi
    
    # Clean up PID file
    if [ -f "$PID_FILE" ]; then
        rm -f "$PID_FILE"
        log_security_event "INFO" "Cleaned up PID file"
    fi
    
    echo -e "${GREEN}✅ OpenHands fully cleaned up${NC}"
    log_security_event "INFO" "OpenHands stopped successfully"
}

function restart_openhands() {
    stop_openhands
    sleep 2
    start_openhands false
}

function is_running() {
    docker ps --format "table {{.Names}}" | grep -q "^${CONTAINER_NAME}$" 2>/dev/null
}

function show_status() {
    if is_running; then
        echo -e "${GREEN}✅ OpenHands is running${NC}"
        echo -e "${BLUE}🌐 URL: $OPENHANDS_URL${NC}"
        echo -e "${BLUE}📊 Container info:${NC}"
        docker ps --filter "name=$CONTAINER_NAME" --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
        
        # Show security info
        echo -e "${BLUE}🔒 Security info:${NC}"
        local container_id=$(docker ps --filter "name=$CONTAINER_NAME" --format "{{.ID}}")
        if [ -n "$container_id" ]; then
            echo "  Container ID: $container_id"
            echo "  Memory limit: $(docker inspect --format='{{.HostConfig.Memory}}' "$container_id" | numfmt --to=iec)"
            echo "  CPU limit: $(docker inspect --format='{{.HostConfig.NanoCpus}}' "$container_id" | awk '{print $1/1000000000}') CPUs"
        fi
    else
        echo -e "${RED}❌ OpenHands is not running${NC}"
    fi
}

function show_logs() {
    if is_running; then
        echo -e "${BLUE}📝 OpenHands container logs:${NC}"
        docker logs --tail 50 "$CONTAINER_NAME"
        
        # Show security log if it exists
        if [ -f "$SCRIPT_DIR/security.log" ]; then
            echo -e "${BLUE}🔒 Security events:${NC}"
            tail -10 "$SCRIPT_DIR/security.log"
        fi
    else
        echo -e "${YELLOW}⚠️  OpenHands is not running${NC}"
    fi
}

function show_security_info() {
    echo -e "${BLUE}🔒 OpenHands Security Information${NC}"
    echo ""
    
    # Show security log
    if [ -f "$SCRIPT_DIR/security.log" ]; then
        echo -e "${BLUE}📋 Security Audit Log:${NC}"
        tail -20 "$SCRIPT_DIR/security.log"
        echo ""
    else
        echo -e "${YELLOW}⚠️  No security events logged yet${NC}"
        echo ""
    fi
    
    # Show Docker security info
    echo -e "${BLUE}🐳 Docker Security Status:${NC}"
    if docker info >/dev/null 2>&1; then
        echo "  ✅ Docker daemon is running"
        
        # Check Docker socket permissions
        local socket_perms=$(stat -c "%a" "/var/run/docker.sock" 2>/dev/null || echo "unknown")
        echo "  🔒 Docker socket permissions: $socket_perms"
        
        # Show running containers
        local container_count=$(docker ps --format "{{.Names}}" | wc -l)
        echo "  📦 Running containers: $container_count"
        
        # Show OpenHands container security
        if is_running; then
            echo "  ✅ OpenHands container is running"
            local container_id=$(docker ps --filter "name=$CONTAINER_NAME" --format "{{.ID}}")
            if [ -n "$container_id" ]; then
                echo "  🏷️  Container ID: $container_id"
                
                # Show security options
                local security_opts=$(docker inspect --format='{{.HostConfig.SecurityOpt}}' "$container_id")
                echo "  🔐 Security options: $security_opts"
                
                # Show capabilities
                local caps=$(docker inspect --format='{{.HostConfig.CapAdd}}' "$container_id")
                echo "  🎯 Added capabilities: $caps"
                
                local caps_drop=$(docker inspect --format='{{.HostConfig.CapDrop}}' "$container_id")
                echo "  🚫 Dropped capabilities: $caps_drop"
                
                # Show read-only status
                local readonly=$(docker inspect --format='{{.HostConfig.ReadonlyRootfs}}' "$container_id")
                echo "  📖 Read-only rootfs: $readonly"
            fi
        else
            echo "  ⏸️  OpenHands container is not running"
        fi
    else
        echo "  ❌ Docker daemon is not running"
    fi
    
    echo ""
    echo -e "${BLUE}🔧 Security Recommendations:${NC}"
    echo "  - Use strong passwords for authentication"
    echo "  - Regularly update OpenHands images"
    echo "  - Monitor security logs for suspicious activity"
    echo "  - Use firewall rules to restrict access"
    echo "  - Consider using HTTPS in production"
}

# Main command handling
case "${1:-start}" in
    start)
        start_openhands false
        ;;
    start-browser)
        start_openhands true
        ;;
    stop)
        stop_openhands
        ;;
    restart)
        restart_openhands
        ;;
    status)
        show_status
        ;;
    logs)
        show_logs
        ;;
    security)
        show_security_info
        ;;
    *)
        show_usage
        exit 1
        ;;
esac
