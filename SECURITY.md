
# Security Policy

## Security Overview

This document outlines the security features and best practices implemented in the OpenHands Apple Silicon setup. We take security seriously and have implemented multiple layers of protection to ensure safe operation.

## 🔒 Security Features

### Container Security

1. **Resource Limits**
   - Memory limit: 4GB (configurable via `OPENHANDS_MEMORY_LIMIT`)
   - CPU limit: 2.0 CPUs (configurable via `OPENHANDS_CPU_LIMIT`)
   - Prevents resource exhaustion attacks

2. **Filesystem Security**
   - Read-only root filesystem
   - Temporary filesystems for `/tmp` and `/run`
   - Prevents persistent malware installation

3. **Capability Management**
   - Drops all capabilities by default
   - Only adds necessary capabilities: `CHOWN`, `DAC_OVERRIDE`, `FOWNER`, `NET_BIND_SERVICE`
   - Follows principle of least privilege

4. **Security Options**
   - `no-new-privileges` prevents privilege escalation
   - Read-only mounts prevent tampering
   - Secure by default configuration

### Docker Security

1. **Socket Security**
   - Monitors Docker socket permissions
   - Warns about insecure permissions
   - Read-only socket mounting where possible

2. **Container Isolation**
   - Dedicated container naming
   - Proper cleanup procedures
   - Isolated runtime environments

3. **Image Security**
   - Uses specific image versions (not just 'latest')
   - Validates image integrity before starting
   - Pulls from official repositories

### Environment Security

1. **Variable Validation**
   - Detects suspicious environment variables
   - Warns about potential secrets in environment
   - Validates configuration before startup

2. **File Permissions**
   - Secure permissions on log files (600)
   - Secure permissions on PID files
   - Regular permission validation

3. **Audit Logging**
   - Comprehensive security event logging
   - Timestamped audit trail
   - Separate security log file

## 🛡️ Security Best Practices

### For Users

1. **Environment Configuration**
   ```bash
   # Set resource limits appropriately
   export OPENHANDS_MEMORY_LIMIT=4g
   export OPENHANDS_CPU_LIMIT=2.0
   
   # Enable verbose logging for debugging
   export LOG_ALL_EVENTS=false
   
   # Use custom container names if needed
   export OPENHANDS_CONTAINER_NAME=openhands-app
   ```

2. **File Permissions**
   - Keep `~/.openhands/` directory permissions secure
   - Regularly review security logs
   - Monitor disk usage in log files

3. **Network Security**
   - Use firewall rules to restrict access to port 3000
   - Consider using reverse proxy with HTTPS in production
   - Monitor network connections to the container

### For Developers

1. **Code Security**
   - All scripts use `set -euo pipefail` for strict error handling
   - Input validation for all user-provided data
   - Secure temporary file handling

2. **Docker Security**
   - Regular security updates for base images
   - Minimal attack surface in container configuration
   - Proper secret management

3. **Logging and Monitoring**
   - Comprehensive audit logging
   - Security event tracking
   - Regular log rotation and cleanup

## 🔍 Security Monitoring

### Security Commands

```bash
# Check security status
./openhands-gui.sh security

# View security logs
tail -f security.log

# Monitor container resources
docker stats openhands-app

# Check Docker socket permissions
stat -c "%a" /var/run/docker.sock
```

### Security Events Logged

- Container start/stop events
- Docker socket permission warnings
- Environment variable validation results
- Image pull operations
- Resource limit violations
- Configuration changes

## 🚨 Security Considerations

### Known Limitations

1. **Docker Socket Access**
   - Container has access to Docker socket (required for OpenHands functionality)
   - This provides significant privileges to the container
   - Monitor container activity carefully

2. **Network Exposure**
   - Default HTTP access on port 3000
   - Consider using HTTPS in production
   - Implement proper authentication

3. **Resource Sharing**
   - Host filesystem mounted at `~/.openhands/`
   - Ensure sensitive data is not stored in this directory
   - Regular cleanup of session data

### Recommendations

1. **Production Deployment**
   - Use reverse proxy with HTTPS termination
   - Implement network segmentation
   - Use firewall rules to restrict access
   - Monitor container activity

2. **Regular Maintenance**
   - Keep Docker images updated
   - Regular security audits
   - Monitor log files for suspicious activity
   - Clean up old containers and images

3. **Incident Response**
   - Regular backups of `~/.openhands/` directory
   - Document security procedures
   - Have incident response plan ready
   - Monitor for security advisories

## 📋 Security Checklist

- [ ] Review security logs regularly
- [ ] Monitor Docker socket permissions
- [ ] Check container resource usage
- [ ] Verify image versions are up-to-date
- [ ] Audit environment variables for secrets
- [ ] Test backup and recovery procedures
- [ ] Review network access controls
- [ ] Monitor for suspicious container activity

## 🤝 Reporting Security Issues

If you discover a security vulnerability, please report it responsibly:

1. **Do not** create public issues for security vulnerabilities
2. **Do** report security issues privately
3. **Do** provide detailed reproduction steps
4. **Do** include affected versions and configurations

### Contact

For security issues, please create a private issue or contact the maintainers directly.

## 🔧 Security Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `OPENHANDS_CONTAINER_NAME` | `openhands-app` | Container name |
| `OPENHANDS_MEMORY_LIMIT` | `4g` | Memory limit for container |
| `OPENHANDS_CPU_LIMIT` | `2.0` | CPU limit for container |
| `LOG_ALL_EVENTS` | `false` | Enable verbose logging |
| `OPENHANDS_RUNTIME_IMAGE` | Specific version | Runtime container image |
| `OPENHANDS_MAIN_IMAGE` | Specific version | Main application image |

### File Permissions

- `security.log`: 600 (user read/write only)
- `openhands.log`: 600 (user read/write only)
- `openhands.pid`: 600 (user read/write only)
- `~/.openhands/`: User permissions only

## 📈 Security Updates

This security policy will be updated regularly to reflect:
- New security best practices
- Discovered vulnerabilities and fixes
- Changes in OpenHands security requirements
- Community feedback and contributions

---

**Last Updated**: $(date +%Y-%m-%d)

**Version**: 1.0

This security policy is part of our commitment to maintaining a secure and reliable OpenHands deployment for Apple Silicon users.
